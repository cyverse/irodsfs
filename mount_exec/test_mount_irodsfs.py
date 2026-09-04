import importlib.machinery
import pathlib
import unittest


helper_path = pathlib.Path(__file__).with_name("mount.irodsfs")
helper = importlib.machinery.SourceFileLoader("mount_irodsfs", str(helper_path)).load_module()


class ReorderArgsTest(unittest.TestCase):
    def test_converts_mount_source_to_url_flag_and_keeps_one_mountpoint(self):
        options, positional_args, timeout = helper.reorder_args([
            "mount.irodsfs",
            "irodsfs",
            "irods://alice:secret@example.org:1247/tempZone/home/alice",
            "/mnt/irods",
            "-o",
            "ro,allow_other,uid=1000,mounttimeout=30",
        ])

        self.assertEqual(
            options,
            [
                "--readonly",
                "-o", "allow_other",
                "--uid", "1000",
                "--url", "irods://alice:secret@example.org:1247/tempZone/home/alice",
            ],
        )
        self.assertEqual(positional_args, ["/mnt/irods"])
        self.assertEqual(timeout, 30)

    def test_rejects_invalid_mounttimeout(self):
        with self.assertRaisesRegex(ValueError, "mounttimeout must be an integer"):
            helper.reorder_args([
                "mount.irodsfs",
                "irods://example.org:1247/tempZone/home/alice",
                "/mnt/irods",
                "-o", "mounttimeout=fast",
            ])

    def test_keeps_generic_fuse_value_options_as_fuse_options(self):
        options, positional_args, timeout = helper.reorder_args([
            "mount.irodsfs",
            "irods://example.org:1247/tempZone/home/alice",
            "/mnt/irods",
            "-o",
            "fsname=custom,max_read=131072,uid=1000",
        ])

        self.assertEqual(
            options,
            [
                "-o", "fsname=custom",
                "-o", "max_read=131072",
                "--uid", "1000",
                "--url", "irods://example.org:1247/tempZone/home/alice",
            ],
        )
        self.assertEqual(positional_args, ["/mnt/irods"])
        self.assertEqual(timeout, 60)


if __name__ == "__main__":
    unittest.main()
