using nfs2iso2nfs.Helpers;
using nfs2iso2nfs.Models;
using System.Globalization;

namespace nfs2iso2nfs
{
    public class Depreciated
    {
        public static Patch Patch = new("");
        public static Nfs Nfs = new();
        public static bool enc = false;
        public static bool keepFiles = false;
        public static string keyFile = ".." + Path.DirectorySeparatorChar + "code" + Path.DirectorySeparatorChar + "htk.bin";
        public static string IsoFile = "game.iso";
        public static string wiiKeyFile = "wii_common_key.bin";

        public static void Main(string[] args)
        {
            Nfs = new Nfs();
            Patch = new Patch(".." + Path.DirectorySeparatorChar + "code" + Path.DirectorySeparatorChar + "fw.img");
            if (!CheckArgs(args))
                return;

            SetupFiles();

            if (!ArgValidation())
                return;

            Nfs.Key = GetKey();
            if (Nfs?.Key == null)
                return;

            if (enc)
                Encrypt();
            else
                Decrypt();

            if (!keepFiles)
            {
                Console.WriteLine("Deleting files!");
                Nfs.DeleteFiles();
                Console.WriteLine("Deleted!");
                Console.WriteLine();
            }
        }
        private static void Decrypt()
        {
            var header = ByteHelper.GetHeader(Nfs.Dir + Path.DirectorySeparatorChar + "hif_000000.nfs");
            Console.WriteLine("Combining NFS Files");
            Nfs.CombineNFSFiles();
            Console.WriteLine("Combined");
            Console.WriteLine();

            Console.WriteLine("Decrypting hif.nfs...");
            NfsHelper.DecryptNFS(Nfs.Hif, Nfs.HifDec, Nfs.Key, Nfs.SectorSize);
            Console.WriteLine("Decrypted!");
            Console.WriteLine();

            Console.WriteLine("Unpacking nfs");
            Nfs.Unpack(header);
            Console.WriteLine("Unpacked");
            Console.WriteLine();

            Console.WriteLine("Manipulate Iso - Decrypt");
            NfsHelper.DecryptManipulateIso(Nfs.HifUnpack, IsoFile, Nfs.SectorSize, Nfs.CommonKey);
            Console.WriteLine("Felt up Iso");
            Console.WriteLine();
        }
        private static void Encrypt()
        {
            Console.WriteLine("Do Patching if applicable!");
            Patch.DoThePatching();
            Console.WriteLine("Patching Done!");
            Console.WriteLine();

            Console.WriteLine("Manipulate Iso - Encrypt");
            var size = NfsHelper.EncryptManipulateIso(IsoFile, Nfs.HifUnpack, Nfs.SectorSize, Nfs.CommonKey);
            Console.WriteLine("Felt up Iso");
            Console.WriteLine();

            Console.WriteLine("Packing nfs");
            var header = Nfs.PackNFS(size);
            Console.WriteLine("Packing complete!");
            Console.WriteLine();

            Console.WriteLine("EncryptNFS");
            NfsHelper.EncryptNFS(Nfs.HifDec, Nfs.Hif, Nfs.Key, Nfs.SectorSize, header);
            Console.WriteLine("Encrypted!");
            Console.WriteLine();

            Console.WriteLine("Split NFS File");
            Nfs.SplitFile();
            Console.WriteLine("Splitted!");
            Console.WriteLine();
        }

        private static bool CheckArgs(string[] args)
        {
            for (int i = 0; i < args.Length; i++)
            {
                switch (args[i])
                {
                    case "-dec":
                        enc = false;
                        break;
                    case "-enc":
                        enc = true;
                        break;
                    case "-keep":
                        keepFiles = true;
                        break;
                    case "-legit":
                        Patch.KeepLegit = true;
                        break;
                    case "-key":
                        if (i == args.Length)
                            return false;
                        keyFile = args[i + 1];
                        i++;
                        break;
                    case "-wiikey":
                        if (i == args.Length)
                            return false;
                        wiiKeyFile = args[i + 1];
                        i++;
                        break;
                    case "-iso":
                        if (i == args.Length)
                            return false;
                        IsoFile = args[i + 1];
                        i++;
                        break;
                    case "-nfs":
                        if (i == args.Length)
                            return false;
                        Nfs.Dir = args[i + 1];
                        i++;
                        break;
                    case "-fwimg":
                        if (i == args.Length)
                            return false;
                        Patch.FwFile = args[i + 1];
                        i++;
                        break;
                    case "-lrpatch":
                        Patch.MapShoulderToTrigger = true;
                        break;
                    case "-wiimote":
                        Patch.VertWiimote = true;
                        break;
                    case "-horizontal":
                        Patch.HorizWiimote = true;
                        break;
                    case "-homebrew":
                        Patch.Homebrew = true;
                        break;
                    case "-passthrough":
                        Patch.PassThrough = true;
                        break;
                    case "-instantcc":
                        Patch.InstantCC = true;
                        break;
                    case "-nocc":
                        Patch.NoCC = true;
                        break;
                    case "-output":
                        Nfs.NfsOutputDirectory = args[i + 1];
                        break;

                    case "-help":
                        Console.WriteLine("+++++ NFS2ISO2NFS v0.6 +++++");
                        Console.WriteLine();
                        Console.WriteLine("-dec            Decrypt .nfs files to an .iso file.");
                        Console.WriteLine("-enc            Encrypt an .iso file to .nfs file(s)");
                        Console.WriteLine("-key <file>     Location of AES key file. DEFAULT: code" + Path.DirectorySeparatorChar + "htk.bin.");
                        Console.WriteLine("-wiikey <file>  Location of Wii Common key file. DEFAULT: wii_common_key.bin.");
                        Console.WriteLine("-iso <file>     Location of .iso file. DEFAULT: game.iso.");
                        Console.WriteLine("-nfs <file>     Location of .nfs files. DEFAULT: current Directory.");
                        Console.WriteLine("-fwimg <file>   Location of fw.img. DEFAULT: code" + Path.DirectorySeparatorChar + "fw.img.");
                        Console.WriteLine("-keep           Don't delete the files produced in intermediate steps.");
                        Console.WriteLine("-legit          Don't patch fw.img to allow fakesigned content");
                        Console.WriteLine("-lrpatch        Map emulated Classic Controller's L & R to Gamepad's ZL & ZR");
                        Console.WriteLine("-wiimote        Emulate a Wii Remote instead of the Classic Controller");
                        Console.WriteLine("-horizontal     Remap Wii Remote d-pad for horizontal usage (implies -wiimote)");
                        Console.WriteLine("-homebrew       Various patches to enable proper homebrew functionality");
                        Console.WriteLine("-passthrough    Allow homebrew to keep using normal wiimotes with gamepad enabled");
                        Console.WriteLine("-instantcc      Report emulated Classic Controller at the very first check");
                        Console.WriteLine("-nocc           Report that no Classic Controller is connected");
                        Console.WriteLine("-output         Location of where the NFS files will be outputted to. DEFAULT: code" + Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar);
                        Console.WriteLine("-help           Print this text.");
                        return false;
                    default:
                        break;
                }
            }
            return true;
        }

        private static void SetupFiles()
        {
            string dir = Directory.GetCurrentDirectory();
            if (!Path.IsPathRooted(keyFile))
                keyFile = dir + Path.DirectorySeparatorChar + keyFile;
            if (!Path.IsPathRooted(IsoFile))
                IsoFile = dir + Path.DirectorySeparatorChar + IsoFile;
            if (!Path.IsPathRooted(wiiKeyFile))
                wiiKeyFile = dir + Path.DirectorySeparatorChar + wiiKeyFile;
            if (!Path.IsPathRooted(Nfs.Dir))
                Nfs.Dir = dir + Path.DirectorySeparatorChar + Nfs.Dir;
            if (!Path.IsPathRooted(Patch.FwFile))
                Patch.FwFile = dir + Path.DirectorySeparatorChar + Patch.FwFile;
        }

        private static bool ArgValidation()
        {
            if (Patch.MapShoulderToTrigger && Patch.HorizWiimote || Patch.MapShoulderToTrigger && Patch.VertWiimote)
            {
                Console.WriteLine("ERROR: Please don't mix patches for Classic Controller and  Wii Remote.");
                return false;
            }


            if (!enc && File.Exists(Nfs.Dir + Path.DirectorySeparatorChar + "hif_000000.nfs"))
            {
                Console.WriteLine("+++++ NFS2ISO +++++");
                Console.WriteLine();
                if (!enc && !File.Exists(Nfs.Dir + Path.DirectorySeparatorChar + "hif_000000.nfs"))
                {
                    Console.WriteLine("ERROR: .nfs files not found! Exiting...");
                    return false;
                }
                else if (!enc && File.Exists(Nfs.Dir + Path.DirectorySeparatorChar + "hif_000000.nfs"))
                {
                    Console.WriteLine("You haven't specified if you want to use nfs2iso or iso2nfs");
                    Console.WriteLine("Found .nfs files! Assuming you want to use nfs2iso...");
                    enc = false;
                }
            }

            else if (enc && File.Exists(IsoFile))
            {
                Console.WriteLine("+++++ ISO2NFS +++++");
                Console.WriteLine();
                if (enc && !File.Exists(IsoFile))
                {
                    Console.WriteLine("ERROR: .iso file not found! Exiting...");
                    return false;
                }
                if (enc && !File.Exists(Patch.FwFile))
                {
                    Console.WriteLine("ERROR: fw.img not found! Exiting...");
                    return false;
                }
                else if (enc && File.Exists(IsoFile))
                {
                    Console.WriteLine("You haven't specified if you want to use nfs2iso or iso2nfs");
                    Console.WriteLine("Found .iso file!  Assuming you want to use iso2nfs...");
                    enc = true;
                }
            }
            else
            {
                Console.WriteLine("You haven't specified if you want to use nfs2iso or iso2nfs");
                Console.WriteLine("Found neither .iso nor .nfs files! Check -help for usage of this program.");
                return false;
            }
            return true;
        }
        public static byte[] ConvertHexStringToByteArray(string hexString)
        {
            if (hexString.Length % 2 != 0)
                throw new ArgumentException(string.Format(CultureInfo.InvariantCulture, "The binary key cannot have an odd number of digits: {0}", hexString));

            var data = new byte[hexString.Length / 2];
            for (int index = 0; index < data.Length; index++)
            {
                var byteValue = hexString.Substring(index * 2, 2);
                data[index] = byte.Parse(byteValue, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            }

            return data;
        }
#pragma warning disable CS8601 // Possible null reference assignment.
#pragma warning disable CS8603 // Possible null reference return.
        private static byte[] GetKey()
        {
            Console.WriteLine("Searching for AES key file...");
            if (!File.Exists(keyFile))
            {
                Console.WriteLine("ERROR: Could not find AES key file! Exiting...");
                return null;
            }
            var key = KeyHelper.GetKey(keyFile);
            if (key == null)
            {
                Console.WriteLine("ERROR: AES key file has wrong file size! Exiting...");
                return null;
            }
            Console.WriteLine("AES key file found!");

            if (Nfs.CommonKey[0] != 0xeb)
            {
                Console.WriteLine("Wii common key not found in source code. Looking for file...");
                if (!File.Exists(wiiKeyFile))
                {
                    Nfs.CommonKey = ConvertHexStringToByteArray("ebe42a225e8593e448d9c5457381aaf7");
                    if (Nfs.CommonKey[0] != 0xeb)
                    {
                        Console.WriteLine("ERROR: Could not find Wii common key file! Exiting...");
                        return null;
                    }
                    else
                        Console.WriteLine("Wii common key has been found.");
                }
                else
                {
                    Nfs.CommonKey = KeyHelper.GetKey(wiiKeyFile);
                    if (Nfs.CommonKey == null)
                    {
                        Console.WriteLine("ERROR: Wii common key file has wrong file size! Exiting...");
                        return null;
                    }
                    Console.WriteLine("Wii Common Key file found!");
                }
            }
            else
                //Console.WriteLine("Wii common key found in source code!");

            Console.WriteLine();
            return key;
        }
#pragma warning disable CS8601 // Possible null reference assignment.
#pragma warning restore CS8603 // Possible null reference return.
    }
}