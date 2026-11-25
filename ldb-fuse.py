#!/usr/bin/env python3

"""
ldb-fuse v1.0.
FUSE mount for LDAP information (e.g. user jpegPhoto, sudoers, etc.) in LDB files (e.g. SSSD cache).
Exported file/directory structure for photos:
  /                               (root)
  ├── users/
  │   └── user@ldapserver.domain/     (user subfolder)
  │       ├── photo.<extension>       (profile picture, if exists)
  │       └── thumbnail.<extension>   (thumbnail picture, if exists)
  └── sudoers.txt   (text file of newline-separated usernames that are authorised
                     for ALL sudo commands on this machine)
"""


from argparse import ArgumentParser, RawTextHelpFormatter
from os.path import isdir
from os import O_WRONLY, O_RDWR, makedirs, removedirs, fsencode, fsdecode
from socket import gethostname
from datetime import datetime

import pyfuse3
import trio
from bidict import bidict
from imghdr import what as imghdr_what
from filecmp import cmp
from errno import ENOENT, EROFS
from ldb import Ldb, FLG_RDONLY
from apscheduler.schedulers.background import BackgroundScheduler
from pydbus import SystemBus

DEFAULT_MOUNTPOINT = "/run/ldb-fuse/"
LOGIN_ICON_CHECK_FREQ_MINS = 30
NANOSECONDS_PER_SECOND = 1000 * 1000 * 1000

class User:
    __slots__ = "name", "uidNumber", "originalModifyTimestamp", "jpegPhoto", "thumbnailPhoto"

    def __init__(self, ldb_res):
        """Initialises a User object from an LDB search result record."""
        self.name = str(ldb_res["name"].get(0))
        self.uidNumber = str(ldb_res["uidNumber"].get(0))
        self.originalModifyTimestamp = str(ldb_res["originalModifyTimestamp"].get(0))
        self.jpegPhoto = (ldb_res["jpegPhoto"].get(0) if ldb_res.get("jpegPhoto") else None)
        self.thumbnailPhoto = (ldb_res["thumbnailPhoto"].get(0) if ldb_res.get("thumbnailPhoto") else None)

    def photo_file_extension(self):
        """
        Returns a string that dictates the file extension for this user's photo.
        The LDAP attribute that stores the photo is (somewhat naïvely) called jpegPhoto, even though the picture data
        can be in any image format. Sticking the extension `.jpeg` on to such files willy-nilly can make certain
        userspace applications like `eog` angry.
        Thus, we need to detect the format to generate an appropriate extension.
        """
        return imghdr_what(None, h=self.jpegPhoto)

    def thumbnail_file_extension(self):
        """
        Returns a string that dictates the file extension for this user's thumbnail image.
        """
        return imghdr_what(None, h=self.thumbnailPhoto)

    def photo_filename(self):
        if not self.jpegPhoto:
            raise pyfuse3.FUSEError(ENOENT)
        return "photo." + self.photo_file_extension()

    def thumbnail_filename(self):
        if not self.thumbnailPhoto:
            raise pyfuse3.FUSEError(ENOENT)
        return "thumbnail." + self.thumbnail_file_extension()


class UserDataProvider:
    """
    Fetches user data from an LDB file, and returns it in a useable format.
    """

    fetch_user_attrs = ["Dn", "name", "uidNumber", "originalModifyTimestamp", "jpegPhoto", "thumbnailPhoto"]
    fetch_sudoer_attrs = ["sudoUser"]

    def __init__(self, dbpath):
        self.dbpath = dbpath
        self.ldb = Ldb()
        # Read-only flag highly advised—for security, and because LDB
        # will clobber the contents of any non-LDB file it's pointed at!
        self.ldb.connect(self.dbpath, FLG_RDONLY)

    def get_all_users(self):
        """
        Fetches all user records.
        :return: Tuple of User objects containing user details.
        """
        results = self.ldb.search(expression="objectCategory=user", attrs=self.fetch_user_attrs)
        return tuple(User(res) for res in results)

    def get_user(self, full_username):
        """
        Searches for a user given their full username "user@ldapserver.domain".
        :return: User object containing user details if a match found; None otherwise.
        """
        results = self.ldb.search(expression=f"name={full_username}", attrs=self.fetch_user_attrs)
        if results:
            return User(results[0])
        return None

    def get_sudoers(self, hostname=None):
        """
        Searches for all users that are allowed to sudo execute "ALL" on this (or another given) hostname.
        :return: Tuple of usernames with sudo permissions.
        """
        if hostname is None:
            hostname = gethostname()
        results = self.ldb.search(expression=f"(&(sudoHost={hostname})(sudoCommand=ALL))", attrs=self.fetch_sudoer_attrs)
        return tuple(str(res["sudoUser"].get(0)).removesuffix('@ldap.luffy.ai') for res in results)

    def get_sudoers_as_bytes(self, hostname=None):
        """
        Transforms the list of sudoers returned from get_sudoers() into a newline-delimited byte string.
        :return: Sudoers list as bytes object.
        """
        return ("\n".join(self.get_sudoers(hostname))+"\n").encode()


class InodeMap:
    """
    Object to link paths to the inode allocated to them. Allows bidirectional lookup.
    Note that this object is purely to match paths to inodes, it does not prescribe anything else about the filesystem.
    In particular, It presupposes any path passed to get_inode() is valid, and will allocate an inode if none exists.
    """

    def __init__(self):
        self._map = bidict()
        self._map["/"] = pyfuse3.ROOT_INODE
        self._next_inode = pyfuse3.ROOT_INODE + 1

    def get_inode(self, path: str):
        """Return inode for the path of a file in the FUSE mount. If this inode doesn't exist, allocate it."""
        try:
            return self._map[path]
        except KeyError:
            new_inode = self._next_inode
            self._map[path] = new_inode
            self._next_inode += 1
            return new_inode

    def get_path(self, inode: int):
        """Return a file's path in the FUSE mount from its inode."""
        try:
            return self._map.inverse[inode]
        except KeyError:
            return pyfuse3.FUSEError(ENOENT)


class FileHandleMap:
    """
    Links an inode to a sequentially generated integer, i.e. file handle.
    This is a read-only file system and I'm lazy, so there's no 'unregister' functionality for now.
    """
    def __init__(self):
        self._map = {}
        self._next_filehandle = 1

    def register(self, inode: int):
        """Generate a new file handle and return it to the caller."""
        filehandle = self._next_filehandle
        self._map[filehandle] = inode
        self._next_filehandle += 1
        return filehandle

    def get_inode(self, filehandle: int):
        """Look up and return an inode from a file handle."""
        return self._map[filehandle]


class LDBFuse(pyfuse3.Operations):
    """
    Implements necessary methods to expose to FUSE.
    """

    def __init__(self, user_data_provider: UserDataProvider):
        super().__init__()
        self._inodes = InodeMap()
        self._filehandles = FileHandleMap()
        self.provider = user_data_provider

    @staticmethod
    def _generate_dir_stat(st_ino=0, atime=0, ctime=0, mtime=0, gid=0, uid=0, mode=0o40555, nlink=0, size=0):
        # File mode for a directory r/x by all and w by no-one: 040555
        stat = pyfuse3.EntryAttributes()
        stat.st_ino = st_ino
        stat.generation = 0  # unused
        stat.entry_timeout = 300
        stat.attr_timeout = 300
        stat.st_atime_ns = atime * NANOSECONDS_PER_SECOND
        stat.st_ctime_ns = ctime * NANOSECONDS_PER_SECOND
        stat.st_mtime_ns = mtime * NANOSECONDS_PER_SECOND
        stat.st_gid = gid
        stat.st_uid = uid
        stat.st_mode = mode
        stat.st_nlink = nlink
        stat.st_size = size
        return stat

    @staticmethod
    def _generate_file_stat(st_ino=0, atime=0, ctime=0, mtime=0, gid=0, uid=0, mode=0o100444, nlink=0, size=0):
        # File mode for a file r by all and w/x by no-one: 0100444
        stat = pyfuse3.EntryAttributes()
        stat.st_ino = st_ino
        stat.generation = 0  # unused
        stat.entry_timeout = 300
        stat.attr_timeout = 300
        stat.st_atime_ns = atime * NANOSECONDS_PER_SECOND
        stat.st_ctime_ns = ctime * NANOSECONDS_PER_SECOND
        stat.st_mtime_ns = mtime * NANOSECONDS_PER_SECOND
        stat.st_gid = gid
        stat.st_uid = uid
        stat.st_mode = mode
        stat.st_nlink = nlink
        stat.st_size = size
        return stat

    def _attr_by_path(self, path: str):
        """Translation layer for lookup() and getattr() that works by path instead of inode."""

        match path.strip("/").split("/"):

            case [""] | ["users"]:
                # Main root or all users subfolder
                return self._generate_dir_stat(st_ino=self._inodes.get_inode(path))

            case ["users", username] if user := self.provider.get_user(username):
                # Individual user's subfolder
                epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
                return self._generate_dir_stat(st_ino=self._inodes.get_inode(path), mtime=epoch_modified)

            case ["users", username, filename] if user := self.provider.get_user(username):
                # Individual file under user's subfolder
                if filename == user.photo_filename():
                    # Photo file
                    epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
                    return self._generate_file_stat(st_ino=self._inodes.get_inode(path), mtime=epoch_modified, size=len(user.jpegPhoto))

                if filename == user.thumbnail_filename():
                    # Thumbnail file
                    epoch_modified = int(datetime.strptime(user.originalModifyTimestamp, "%Y%m%d%H%M%SZ").timestamp())
                    return self._generate_file_stat(st_ino=self._inodes.get_inode(path), mtime=epoch_modified, size=len(user.thumbnailPhoto))

                raise pyfuse3.FUSEError(ENOENT)

            case ["sudoers.txt"]:
                # Sudoers file
                return self._generate_file_stat(st_ino=self._inodes.get_inode(path), size=len(self.provider.get_sudoers_as_bytes()))

        raise pyfuse3.FUSEError(ENOENT)

    def _file_data_by_path(self, path: str):
        """Returns file byte data."""

        match path.strip("/").split("/"):

            case ["users", username, filename] if user := self.provider.get_user(username):
                # Individual file under user's subfolder
                if user.jpegPhoto and filename == user.photo_filename():
                    return user.jpegPhoto
                if user.thumbnailPhoto and filename == user.thumbnail_filename():
                    return user.thumbnailPhoto
                raise pyfuse3.FUSEError(ENOENT)

            case ["sudoers.txt"]:
                # Sudoers file
                return self.provider.get_sudoers_as_bytes()

        raise pyfuse3.FUSEError(ENOENT)

    def _file_data_by_inode(self, inode: int):
        return self._file_data_by_path(self._inodes.get_path(inode))

    async def getattr(self, inode: int, ctx: pyfuse3.RequestContext):
        """Returns filesystem attributes (type of file object, permissions, etc)"""
        return self._attr_by_path(self._inodes.get_path(inode))

    async def lookup(self, parent_inode: int, name: bytes, ctx: pyfuse3.RequestContext):
        """From pyfuse3 docs: "Look up a directory entry by name and get its attributes." """
        path = self._inodes.get_path(parent_inode) + "/" + fsdecode(name)
        attr = self._attr_by_path(path)
        return attr

    async def opendir(self, inode: int, ctx: pyfuse3.RequestContext):
        # Nothing to do here really. Return inode as filehandle.
        filehandle = self._filehandles.register(inode)
        return filehandle

    async def readdir(self, fh: int, start_id: int, token: pyfuse3.ReaddirToken):
        """Yields directory contents."""
        entries = [".", ".."]

        # For dirs, filehandle is inode.
        path = self._inodes.get_path(self._filehandles.get_inode(fh))
        match path.strip("/").split("/"):

            case [""]:
                # Root
                entries.extend(["users", "sudoers.txt"])

            case ["users"]:
                # All users subfolder
                allusers = self.provider.get_all_users()
                entries.extend(user.name for user in allusers)

            case ["users", username] if user := self.provider.get_user(username):
                # Individual user's subfolder
                if user.jpegPhoto:
                    entries.append(user.photo_filename())
                if user.thumbnailPhoto:
                    entries.append(user.thumbnail_filename())

            case _:
                raise pyfuse3.FUSEError(ENOENT)

        entries = entries[start_id:]  # Cut down list to requested size
        for entry_index, entry in enumerate(entries):
            pyfuse3.readdir_reply(token, fsencode(entry), self._attr_by_path(path), entry_index + 1)

    async def open(self, inode: int, flags, ctx):
        if flags & (O_WRONLY | O_RDWR):
            raise pyfuse3.FUSEError(EROFS)
        filehandle = self._filehandles.register(inode)
        return pyfuse3.FileInfo(fh=filehandle, keep_cache=True)

    async def read(self, fh, offset, length):
        return self._file_data_by_inode(self._filehandles.get_inode(fh))[offset:offset+length]

    async def statfs(self, ctx):
        """Returns dummy info"""
        s = pyfuse3.StatvfsData()
        s.f_bsize = 512
        s.f_frsize = 512
        s.f_blocks = 0
        s.f_bfree = 0
        s.f_bavail = 0
        s.f_files = 0
        s.f_ffree = 0
        s.f_favail = 0
        s.f_namemax = 255
        return s


def dbus_set_icon_path(uid, icon_path):
    """Set a user's login icon to the contents of an existing file via DBus"""
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}")\
                      .SetIconFile(icon_path)


def dbus_get_icon_path(uid):
    """Get the path of a user's current login icon via DBus"""
    return SystemBus().get("org.freedesktop.Accounts", f"/org/freedesktop/Accounts/User{uid}")\
                      .Get('org.freedesktop.Accounts.User', 'IconFile')


def sync_user_icons(user_data_provider, user_data_path):
    """
    For all users in a provider, checks for the existence of a jpegPhoto.
    If available, and it is different to the user's current profile icon, set it as their new icon.
    """
    for user in user_data_provider.get_all_users():
        if user.jpegPhoto:
            fuse_photo_path = f"{user_data_path}/{user.name}/{user.photo_filename()}"
            try:
                # NB: Sometimes SSSD caches users that haven't yet logged on locally.
                # In this case, dbus raises a KeyError in get_icon_path(), and we simply move to the next iteration.
                if not cmp(dbus_get_icon_path(user.uidNumber), fuse_photo_path):
                    dbus_set_icon_path(user.uidNumber, fuse_photo_path)
            except KeyError:
                continue
            except FileNotFoundError:
                # No existing icon, so use the one from the provided path.
                dbus_set_icon_path(user.uidNumber, fuse_photo_path)


class Mountpoint:
    """Context handler for FUSE mounts that creates mount point beforehand, and removes afterward."""
    def __init__(self, path):
        self.path = path

    def __enter__(self):
        if not isdir(self.path):
            makedirs(self.path)
            if not isdir(self.path):
                raise NotADirectoryError(f"Can't create mount point {self.path}.")

    def __exit__(self, exception_type, exception_value, exception_traceback):
        removedirs(self.path)


class Filesystem:
    """Very simple context manager that just enforces cleanup with `close()` after using the FS."""
    def __enter__(self):
        pass

    def __exit__(self, exception_type, exception_value, exception_traceback):
        pyfuse3.close(unmount=True)


def main():

    parser = ArgumentParser(description=__doc__, formatter_class=RawTextHelpFormatter)
    parser.add_argument("dbpath", help="SSS database location")
    parser.add_argument("--mountpoint", help="Path that LDB data will be mounted under.", default=DEFAULT_MOUNTPOINT)
    parser.add_argument("--allow-other", help="Allow users other than root to access mounts", action="store_true")
    parser.add_argument("--sync-user-icons", help=f"Every {LOGIN_ICON_CHECK_FREQ_MINS} mins, set login icon via D-Bus for users that have a new jpegPhoto. Will overwrite previous picture.", action="store_true")
    args = parser.parse_args()
    provider = UserDataProvider(args.dbpath)

    if args.sync_user_icons:
        scheduler = BackgroundScheduler()
        scheduler.add_job(func=sync_user_icons,
                          args=(provider, f"{args.mountpoint}/users"),
                          trigger="interval",
                          minutes=LOGIN_ICON_CHECK_FREQ_MINS
                          )
        scheduler.start()

    fuse_options = set(pyfuse3.default_options)
    fuse_options.discard('default_permissions')
    fuse_options.add('fsname=ldbfuse')
    if args.allow_other:
        fuse_options.add('allow_other')

    with Mountpoint(args.mountpoint):
        with Filesystem():
            pyfuse3.init(LDBFuse(provider), args.mountpoint, fuse_options)
            trio.run(pyfuse3.main)


if __name__ == "__main__":
    main()
