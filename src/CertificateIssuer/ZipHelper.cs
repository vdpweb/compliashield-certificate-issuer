
namespace CompliaShield.CertificateIssuer.ConsoleApp
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;
    using ICSharpCode.SharpZipLib.Zip;

    public class ZipHelper
    {

        public byte[] diskLess()
        {
            MemoryStream ms = new MemoryStream();
            StreamWriter sw = new StreamWriter(ms);
            sw.WriteLine("HELLO!");
            sw.WriteLine("I WANT TO SAVE THIS FILE AS A .TXT FILE WITHIN TWO FOLDERS");
            sw.Flush(); //This is required or you get a blank text file :)
            ms.Position = 0;

            // create the ZipEntry archive from the txt file in memory stream ms
            MemoryStream outputMS = new System.IO.MemoryStream();

            ZipOutputStream zipOutput = new ZipOutputStream(outputMS);

            ZipEntry ze = new ZipEntry(@"dir1/dir2/whatever.txt");
            zipOutput.PutNextEntry(ze);
            zipOutput.Write(ms.ToArray(), 0, Convert.ToInt32(ms.Length));
            zipOutput.Finish();
            zipOutput.Close();
            byte[] byteArrayOut = outputMS.ToArray();
            outputMS.Close();

            ms.Close();

            return byteArrayOut;

        }

    }
}
