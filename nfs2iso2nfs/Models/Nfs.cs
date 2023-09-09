using nfs2iso2nfs.Helpers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace nfs2iso2nfs.Models
{
    public class Nfs
    {
        public string temp = "";
        public string Hif = "hif.nfs";
        public string HifDec = "hif_dec.nfs";
        public string HifUnpack = "hif_unpack.nfs";
        public string Dir { get; set; } = "";
        public int HeaderSize = 0x200;
        public int SectorSize = 0x8000;
        public int Size = 0xFA00000;

        public byte[] CommonKey { get; set; } = { 0xeb, 0xe4, 0x2a, 0x22, 0x5e, 0x85, 0x93, 0xe4, 0x48, 0xd9, 0xc5, 0x45, 0x73, 0x81, 0xaa, 0xf7 };
        public byte[] Key { get; set; } = Array.Empty<byte>();
        
        public string NfsOutputDirectory { get; set; } = Directory.GetCurrentDirectory() + Path.DirectorySeparatorChar;
        public void CombineNFSFiles()
        {
            using var nfs = new BinaryWriter(File.OpenWrite(Hif));
            var nfsNo = -1;
            while (File.Exists(Dir + Path.DirectorySeparatorChar + "hif_" + string.Format("{0:D6}", nfsNo + 1) + ".nfs"))
                nfsNo++;

            for (var i = 0; i <= nfsNo; i++)
            {
                var nfsTemp = new BinaryReader(File.OpenRead(Dir + Path.DirectorySeparatorChar + "hif_" + string.Format("{0:D6}", i) + ".nfs"));
                if (i == 0)
                {
                    nfsTemp.ReadBytes(HeaderSize);
                    nfs.Write(nfsTemp.ReadBytes((int)nfsTemp.BaseStream.Length - HeaderSize));
                }
                else
                    nfs.Write(nfsTemp.ReadBytes((int)nfsTemp.BaseStream.Length));
            }
        }
        public void Decrypt(string IsoFile)
        {
            var header = ByteHelper.GetHeader(Dir + Path.DirectorySeparatorChar + "hif_000000.nfs");
            Console.WriteLine("Combining NFS Files");
            CombineNFSFiles();
            Console.WriteLine("Combined");
            Console.WriteLine();

            Console.WriteLine("Decrypting hif.nfs...");
            NfsHelper.DecryptNFS(Hif, HifDec, Key, SectorSize);
            Console.WriteLine("Decrypted!");
            Console.WriteLine();

            Console.WriteLine("Unpacking nfs");
            Unpack(header);
            Console.WriteLine("Unpacked");
            Console.WriteLine();

            Console.WriteLine("Manipulate Iso - Decrypt");
            NfsHelper.DecryptManipulateIso(HifUnpack, IsoFile, SectorSize, CommonKey);
            Console.WriteLine("Felt up Iso");
            Console.WriteLine();
        }
        public void Encrypt(Patch patch, string IsoFile)
        {
            Console.WriteLine("Do Patching if applicable!");
            patch.DoThePatching();
            Console.WriteLine("Patching Done!");
            Console.WriteLine();

            Console.WriteLine("Manipulate Iso - Encrypt");
            var size = NfsHelper.EncryptManipulateIso(IsoFile, HifUnpack, SectorSize, CommonKey);
            Console.WriteLine("Felt up Iso");
            Console.WriteLine();

            Console.WriteLine("Packing nfs");
            var header = PackNFS(size);
            Console.WriteLine("Packing complete!");
            Console.WriteLine();

            Console.WriteLine("EncryptNFS");
            NfsHelper.EncryptNFS(HifDec, Hif, Key, SectorSize, header);
            Console.WriteLine("Encrypted!");
            Console.WriteLine();

            Console.WriteLine("Split NFS File");
            _ = SplitFile().Result;
            Console.WriteLine("Splitted!");
            Console.WriteLine();
        }
        public void DeleteFiles()
        {
            foreach (var file in new List<string>() { Hif, HifDec, HifUnpack })
                File.Delete(file);
            Directory.Delete(temp, true);
        }
        public void SetDir(string dir)
        {
            Dir = dir;
        }
        public void Unpack(byte[] header)
        {
            using var er = new BinaryReader(File.OpenRead(HifDec));
            using var ew = new BinaryWriter(File.OpenWrite(HifUnpack));

            int numberOfParts = 0x1000000 * header[0x10] + 0x10000 * header[0x11] + 0x100 * header[0x12] + header[0x13];
            long start, length;
            long pos = 0x0;
            long j = 0;
            for (int i = 0; i < numberOfParts; i++)
            {
                start = (long)SectorSize * (0x1000000 * header[0x14 + i * 0x8] + 0x10000 * header[0x15 + i * 0x8] + 0x100 * header[0x16 + i * 0x8] + header[0x17 + i * 0x8]);
                length = (long)SectorSize * (0x1000000 * header[0x18 + i * 0x8] + 0x10000 * header[0x19 + i * 0x8] + 0x100 * header[0x1A + i * 0x8] + header[0x1B + i * 0x8]);
                j = start - pos;
                while (j > 0)
                {
                    ew.Write(ByteHelper.BuildZero(SectorSize));
                    j -= SectorSize;
                }
                j = length;
                while (j > 0)
                {
                    ew.Write(er.ReadBytes(SectorSize));
                    j -= SectorSize;
                }
                pos = start + length;
            }
        }
        public byte[] PackNFS(long[] sizeInfo)
        {
            using var er = new BinaryReader(File.OpenRead(HifUnpack));
            using var ew = new BinaryWriter(File.OpenWrite(HifDec));
            byte[] header = new byte[0x200];

            for (int i = 0; i < 0x200; i++)
                header[i] = 0xff;

            header[0x0] = 0x45;
            header[0x1] = 0x47;
            header[0x2] = 0x47;
            header[0x3] = 0x53;

            header[0x4] = 0x00;
            header[0x5] = 0x01;
            header[0x6] = 0x10;
            header[0x7] = 0x11;

            header[0x8] = 0x00;
            header[0x9] = 0x00;
            header[0xA] = 0x00;
            header[0xB] = 0x00;

            header[0xC] = 0x00;
            header[0xD] = 0x00;
            header[0xE] = 0x00;
            header[0xF] = 0x00;

            header[0x10] = 0x00;
            header[0x11] = 0x00;
            header[0x12] = 0x00;
            header[0x13] = 0x03;

            header[0x14] = 0x00;
            header[0x15] = 0x00;
            header[0x16] = 0x00;
            header[0x17] = 0x00;

            header[0x18] = 0x00;
            header[0x19] = 0x00;
            header[0x1A] = 0x00;
            header[0x1B] = 0x01;

            header[0x1C] = 0x00;
            header[0x1D] = 0x00;
            header[0x1E] = 0x00;
            header[0x1F] = 0x08;

            header[0x20] = 0x00;
            header[0x21] = 0x00;
            header[0x22] = 0x00;
            header[0x23] = 0x02;

            header[0x24] = (byte)((sizeInfo[0] / 0x8000) / 0x1000000);
            header[0x25] = (byte)(((sizeInfo[0] / 0x8000) / 0x10000) % 0x100);
            header[0x26] = (byte)(((sizeInfo[0] / 0x8000) / 0x100) % 0x10000);
            header[0x27] = (byte)((sizeInfo[0] / 0x8000) % 0x1000000);

            header[0x28] = (byte)((sizeInfo[1] / 0x8000) / 0x1000000);
            header[0x29] = (byte)(((sizeInfo[1] / 0x8000) / 0x10000) % 0x100);
            header[0x2A] = (byte)(((sizeInfo[1] / 0x8000) / 0x100) % 0x10000);
            header[0x2B] = (byte)((sizeInfo[1] / 0x8000) % 0x1000000);

            header[0x1FC] = 0x53;
            header[0x1FD] = 0x47;
            header[0x1FE] = 0x47;
            header[0x1FF] = 0x45;

            int numberOfParts = 0x1000000 * header[0x10] + 0x10000 * header[0x11] + 0x100 * header[0x12] + header[0x13];
            long start, length;
            long pos = 0x0;
            long j = 0;
            for (int i = 0; i < numberOfParts; i++)
            {
                start = (long)SectorSize * ((long)0x1000000 * (long)header[0x14 + i * 0x8] + (long)0x10000 * (long)header[0x15 + i * 0x8] + (long)0x100 * (long)header[0x16 + i * 0x8] + (long)header[0x17 + i * 0x8]);
                length = (long)SectorSize * ((long)0x1000000 * (long)header[0x18 + i * 0x8] + (long)0x10000 * (long)header[0x19 + i * 0x8] + (long)0x100 * (long)header[0x1A + i * 0x8] + (long)header[0x1B + i * 0x8]);
                j = start - pos;
                Console.WriteLine("Delete zero segment " + i + " of size 0x" + Convert.ToString(j, 16));
                while (j > 0)
                {
                    er.ReadBytes(SectorSize);
                    j -= SectorSize;
                }
                Console.WriteLine("Writing data segment " + i + " of size 0x" + Convert.ToString(length, 16));
                j = length;
                while (j > 0)
                {
                    ew.Write(er.ReadBytes(SectorSize));
                    j -= SectorSize;
                }
                pos = start + length;
            }
            return header;
        }
        public async Task<bool> SplitFile()
        {
            using var nfs = new BinaryReader(File.OpenRead(Hif));
            long size = nfs.BaseStream.Length;
            int i = 0;

            do
            {
                Console.WriteLine("Building hif_" + string.Format("{0:D6}", i) + ".nfs...");
                //var nfsTemp = new BinaryWriter(File.OpenWrite());
                File.WriteAllBytes(NfsOutputDirectory + "hif_" + string.Format("{0:D6}", i) + ".nfs", nfs.ReadBytes(size > Size ? Size : (int)size));
                //nfsTemp.Write();
                size -= Size;
                i++;
            } while (size > 0);
            return true;
        }

        public void SetTemp(string temp)
        {
            if(Directory.Exists(temp)) Directory.Delete(temp, true);
            this.temp = temp;
            Directory.CreateDirectory(temp);
            Hif = Path.Combine(temp, Hif);
            HifDec = Path.Combine(temp, HifDec);
            HifUnpack = Path.Combine(temp, HifUnpack);
        }

        public void SetOut(string outpath)
        {
            NfsOutputDirectory = outpath;
        }
    }
}
