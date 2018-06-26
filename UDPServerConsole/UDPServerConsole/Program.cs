using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace UDPServerConsole
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct TEST
        {
            public string Buffer;
            public int number;

            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 20)]
            public string aString;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 20)]
            public byte[] innerTestArray;
        }

        public const byte HEADER_AUTH_FAILED = 0x00;
        public const byte HEADER_AUTH_SUCCEEDED = 0x01;
        public const byte HEADER_AUTH_TOKEN = 0x02;
        public const byte HEADER_SERVER_RESPONSE = 0xFF;
        public const int port = 600;
        public const string password = "pass";
        public static List<ClientInfo> clientList = new List<ClientInfo>();
        public static UdpClient serverSocket = null;
        public static IPEndPoint clientEndpoint = null;
        public static byte[] receivedData = null;

        static void Main(string[] args)
        {
            /* Server return headers (first byte):
             * 0x00 = (Authentication failed). Client's ip-address will be removed from clientlist.
             * 0x01 = (Authentication succeeded). ClientInfo.authenticated will be set true for corresponding ip-address.
             * 0x02 = (Authentication required). Authentication token will be created and sent to the client with this header. Client's ip-address and token will be added to clientlist aswell.
             */

            while (true)
            {
                serverSocket = new UdpClient(port);
                clientEndpoint = new IPEndPoint(IPAddress.Any, 0);
                receivedData = serverSocket.Receive(ref clientEndpoint);
                serverSocket.Connect(clientEndpoint);
                ClientStatus cs = CheckAuthenticationStatus(clientEndpoint.Address);

                switch (cs)
                {
                    case ClientStatus.CLIENT_AUTH_NEW:
                        GenerateSendToken();
                        break;

                    case ClientStatus.CLIENT_AUTH_RECEIVED:
                        CheckAuthResponse(receivedData);
                        break;

                    case ClientStatus.CLIENT_AUTH_OK:
                        HandleData(receivedData);
                        break;
                }
                serverSocket.Close();
            }
        }

        public static void HandleData(byte[] data)
        {
            TEST strN = structFromBytes(data);
            Console.WriteLine("HANDLE DATA at SERVER");
            Console.WriteLine("struct size: " + Marshal.SizeOf(strN));
            Console.WriteLine("data size: " +  data.Length);
            Console.WriteLine("message: " + strN.aString);
            Console.WriteLine("message size: " + strN.aString.Length);
            Console.WriteLine("----");
            Console.WriteLine("");

            var response = Encoding.ASCII.GetBytes(strN.aString);
            serverSocket.Send((new byte[] { HEADER_SERVER_RESPONSE }).Concat(response).ToArray(), response.Length + 1);
        }

        static TEST structFromBytes(byte[] arr)
        {
            TEST str = new TEST();
            int size = Marshal.SizeOf(str);
            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.Copy(arr, 0, ptr, size);
            str = (TEST)Marshal.PtrToStructure(ptr, str.GetType());
            Marshal.FreeHGlobal(ptr);
            return str;
        }

        public static void CheckAuthResponse(byte[] data)
        {
            string response = Encoding.ASCII.GetString(data);
            int clientId = GetClientIdByIp(clientEndpoint.Address);

            if (response.Equals(ComputeHash(clientList[clientId].token + password)))
            {
                clientList[clientId].authenticated = true;
                serverSocket.Send(new byte[] { HEADER_AUTH_SUCCEEDED }, 1);
                return;
            }

            clientList.RemoveAt(clientId);
            serverSocket.Send(new byte[] { HEADER_AUTH_FAILED }, 1);
        }

        public static void GenerateSendToken()
        {
            string guidString = Guid.NewGuid().ToString();
            byte[] guid = Encoding.ASCII.GetBytes(guidString);
            byte[] finalPacket = (new byte[] { HEADER_AUTH_TOKEN }).Concat(guid).ToArray();

            serverSocket.Send(finalPacket, finalPacket.Length);
            clientList.Add(new ClientInfo(clientEndpoint.Address));
            clientList[GetClientIdByIp(clientEndpoint.Address)].token = guidString;
        }

        public static ClientStatus CheckAuthenticationStatus(IPAddress ip)
        {

            ClientInfo clientdata = GetClientInfoByIp(ip);

            if (clientdata != null)
            {
                if (clientdata.authenticated)
                    return ClientStatus.CLIENT_AUTH_OK;

                else
                    return ClientStatus.CLIENT_AUTH_RECEIVED;
            }

            else
                return ClientStatus.CLIENT_AUTH_NEW;

        }

        public static ClientInfo GetClientInfoByIp(IPAddress ip)
        {
            return clientList.Find(i => (i.ip.Equals(ip)));
        }


        public static int GetClientIdByIp(IPAddress ip)
        {
            return clientList.FindIndex(i => (i.ip.Equals(ip)));
        }


        public static String ComputeHash(String value)
        {
            using (SHA256 hash = SHA256Managed.Create())
            {
                return String.Join("", hash.ComputeHash(Encoding.UTF8.GetBytes(value)).Select(item => item.ToString("x2")));
            }
        }

    }

    class ClientInfo
    {
        public IPAddress ip;
        public bool authenticated = false;
        public string token;

        public ClientInfo(IPAddress ip = null)
        {
            this.ip = ip;
        }
    }

    enum ClientStatus
    {
        CLIENT_AUTH_NEW = 0,
        CLIENT_AUTH_RECEIVED = 2,
        CLIENT_AUTH_OK = 1
    };
}  