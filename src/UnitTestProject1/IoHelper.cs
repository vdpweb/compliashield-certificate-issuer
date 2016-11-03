using System.IO;
using System.Reflection;

namespace UnitTestProject1
{
    public static class IoHelper
    {

        public static Stream GetStream(string stringData)
        {
            MemoryStream stream = new MemoryStream();
            StreamWriter writer = new StreamWriter(stream);
            writer.Write(stringData);
            writer.Flush();
            stream.Position = 0;
            return stream;
        }

        public static string GetString(Stream inputStream)
        {
            string output;
            using (StreamReader reader = new StreamReader(inputStream))
            {
                output = reader.ReadToEnd();
            }
            return output;
        }

        // Streams.PipeAll(unc, output);

        public static void WriteStream(Stream inputStream, ref byte[] dataBytes)
        {
            using (Stream outputStream = inputStream)
            {
                outputStream.Write(dataBytes, 0, dataBytes.Length);
            }
        }
    }
}
