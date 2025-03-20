using System;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Threading;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using MySql.Data.MySqlClient;

namespace G8_Lockdown
{
    public partial class main : ServiceBase
    {
        private static string connectionString = "";

        private Timer processCheckTimer;
        private Timer untrustedCheckTimer;
        private Timer externalDriveCheckTimer;
        private Process[] initialProcesses;
        private string logFilePath = @"C:\Windows\GhostGuard\logs\ghostguard_general.log";
        private string logFilePathhardware = @"C:\Windows\GhostGuard\logs\ghostguard_hardware.log";
        private string logFilePathuntrusted = @"C:\Windows\GhostGuard\logs\ghostguard_untrusted.log";
        private string logFileDMA = @"C:\Windows\GhostGuard\logs\ghostguard_dma.log";

        private HashSet<string> allowedHashes = new HashSet<string>();
        public main()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            Log("GG Enabled");

            allowedHashes = grabHashes();

            detectDMA();

            Thread.Sleep(1000);

            initialProcesses = Process.GetProcesses();
            untrustedCheckTimer = new Timer(checkUntrustedProcesses, null, 0, 1000);
            processCheckTimer = new Timer(checkProc, null, 0, 1000);
            externalDriveCheckTimer = new Timer(checkAndEjectExternalDrives, null, 0, 5000);
        }

        private void checkUntrustedProcesses(object state)
        {
            Process[] currentProcesses = Process.GetProcesses();

            foreach (var process in currentProcesses)
            {
                if (process.Id == Process.GetCurrentProcess().Id)
                {
                    continue;
                }

                try
                {
                    string filePath = process.MainModule.FileName;

                    if (!filePath.StartsWith(@"C:\"))
                    {
                        string fileHash = GetFileHash(filePath);

                        LogUntrusted($"Untrusted process detected: {process.ProcessName} (Path: {filePath}, Hash: {fileHash})");

                        LogUntrusted($"Terminating untrusted process: {process.ProcessName} (ID: {process.Id})");
                        process.Kill();
                    }
                }
                catch (Exception ex)
                {
                }
            }
        }



        private void LogUntrusted(string message)
        {
            try
            {
                string logDir = Path.GetDirectoryName(logFilePathuntrusted);
                if (!Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                using (StreamWriter writer = new StreamWriter(logFilePathuntrusted, true))
                {
                    writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
                    writer.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Untrusted logging failed: {ex.Message}");
            }
        }
        protected override void OnStop()
        {
            processCheckTimer?.Dispose();

            Log("Service stopped.");
        }
        private HashSet<int> scannedProcessIds = new HashSet<int>();

        private void checkProc(object state)
        {
            Process[] currentProcesses = Process.GetProcesses();

            foreach (var process in currentProcesses)
            {
                if (process.Id == Process.GetCurrentProcess().Id)
                {
                    continue;
                }

                if (scannedProcessIds.Contains(process.Id))
                {
                    continue;
                }

                scannedProcessIds.Add(process.Id);

                try
                {
                    string filePath = process.MainModule.FileName;

                    string fileHash = GetFileHash(filePath);

                    if (allowedHashes.Contains(fileHash))
                    {
                        continue;
                    }

                    Log($"killed proc: {process.ProcessName} {fileHash}");
                    process.Kill();
                }
                catch (Exception ex)
                {
                    
                }
            }
        }
        public HashSet<string> grabHashes()
        {
            var allowedHashes = new HashSet<string>();

            using (MySqlConnection connection = new MySqlConnection(connectionString))
            {
                try
                {
                    connection.Open();
                    Log("Database connection opened successfully");

                    string query = "SELECT app_identifier FROM apps";
                    MySqlCommand cmd = new MySqlCommand(query, connection);
                    MySqlDataReader reader = cmd.ExecuteReader();

                    while (reader.Read())
                    {
                        string appIdentifier = reader.GetString("app_identifier");
                        allowedHashes.Add(appIdentifier);

                        Log($"Retrieved allowed hash from database: {appIdentifier}");
                    }

                    Log("Finished retrieving allowed hashes from the database.");
                }
                catch (Exception ex)
                {
                    Log($"Error retrieving allowed hashes from database: {ex.Message}");
                }
            }

            return allowedHashes;
        }


        private string GetFileHash(string filePath)
        {
            using (var sha256 = SHA256.Create())
            {
                using (var stream = File.OpenRead(filePath))
                {
                    byte[] hashBytes = sha256.ComputeHash(stream);
                    return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
            }
        }
        private void Log(string message)
        {
            try
            {
                string logDir = Path.GetDirectoryName(logFilePath);
                if (!Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                using (StreamWriter writer = new StreamWriter(logFilePath, true))
                {
                    writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
                    writer.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Logging failed: {ex.Message}");
            }
        }

        private void hardwareLog(string message)
        {
            try
            {
                string logDir = Path.GetDirectoryName(logFilePathhardware);
                if (!Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                using (StreamWriter writer = new StreamWriter(logFilePathhardware, true))
                {
                    writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
                    writer.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Untrusted logging failed: {ex.Message}");
            }
        }

        private void dmaLog(string message)
        {
            try
            {
                string logDir = Path.GetDirectoryName(logFileDMA);
                if (!Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }

                using (StreamWriter writer = new StreamWriter(logFileDMA, true))
                {
                    writer.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {message}");
                    writer.Flush();
                }
            }
            catch (Exception ex)
            {
                hardwareLog(ex.ToString());
            }
        }

        private const long MAX_DRIVE_SIZE = 256L * 1024L * 1024L * 1024L;

        private void checkAndEjectExternalDrives(object state)
        {
            DriveInfo[] allDrives = DriveInfo.GetDrives();

            foreach (var drive in allDrives)
            {
                if (drive.DriveType == DriveType.Removable && drive.IsReady)
                {
                    try
                    {
                        if (drive.TotalSize < MAX_DRIVE_SIZE)
                        {
                            hardwareLog($"External drive detected 0xCE000F --> MAX_DRIVE_SIZE --? Requirements lacking - Attempting to eject drive");
                            EjectDrive(drive.Name.TrimEnd('\\'));
                        }
                        else
                        {
                            hardwareLog($"External drive detected 0xCE000F --> MAX_DRIVE_SIZE | Skipping eject.");
                        }
                    }
                    catch (Exception ex)
                    {
                        hardwareLog($"Error handling external drive {drive.Name}: {ex.Message}");
                    }
                }
            }
        }


        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, IntPtr lpInBuffer, uint nInBufferSize, IntPtr lpOutBuffer, uint nOutBufferSize, out uint lpBytesReturned, IntPtr lpOverlapped);

        private const uint IOCTL_STORAGE_EJECT_MEDIA = 0x2D4808;

        private void EjectDrive(string driveLetter)
        {
            try
            {
                string volume = $"\\\\.\\{driveLetter}";
                using (FileStream fs = new FileStream(volume, FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                {
                    DeviceIoControl(fs.SafeFileHandle.DangerousGetHandle(), IOCTL_STORAGE_EJECT_MEDIA, IntPtr.Zero, 0, IntPtr.Zero, 0, out uint bytesReturned, IntPtr.Zero);
                }

                hardwareLog($"GhostGuard ejected drive: {driveLetter}");
            }
            catch (Exception ex)
            {
                hardwareLog($"Failed to eject drive {driveLetter}: {ex.Message}");
            }
        }

        private void detectDMA()
        {
            const uint DIGCF_PRESENT = 0x00000002;
            const uint DIGCF_ALLCLASSES = 0x00000004;
            IntPtr hDevInfo = SetupDiGetClassDevs(IntPtr.Zero, null, IntPtr.Zero, DIGCF_ALLCLASSES);

            if (hDevInfo == IntPtr.Zero)
            {
                dmaLog("Failed to get device info.");
                return;
            }

            dmaLog("Device info retrieved.");

            SP_DEVINFO_DATA devInfoData = new SP_DEVINFO_DATA();
            devInfoData.cbSize = Marshal.SizeOf(typeof(SP_DEVINFO_DATA));

            int index = 0;
            bool deviceFound = false;

            while (SetupDiEnumDeviceInfo(hDevInfo, index, ref devInfoData))
            {
                StringBuilder deviceName = new StringBuilder(256);
                StringBuilder vendorID = new StringBuilder(256);

                uint requiredSize;

                if (SetupDiGetDeviceRegistryProperty(hDevInfo, ref devInfoData, SPDRP_DEVICEDESC, out _, deviceName, deviceName.Capacity, out requiredSize))
                {
                    string hardwareID = vendorID.ToString();
                    if (hardwareID.Contains("PCI\\VEN_"))
                    {
                        dmaLog($"Device {index}: Name: {deviceName}");
                    }
                }

                if (SetupDiGetDeviceRegistryProperty(hDevInfo, ref devInfoData, SPDRP_HARDWAREID, out _, vendorID, vendorID.Capacity, out requiredSize))
                {
                    string hardwareID = vendorID.ToString();
                    if (hardwareID.Contains("PCI\\VEN_"))
                    {
                        dmaLog($"Device {index}: Name: {deviceName}");
                        dmaLog($"Device {index}: Hardware ID: {vendorID}");
                        dmaLog($"Device {index}: PCI Device Detected.");
                        dmaLog("-----------------------------------");
                        deviceFound = true;
                    }
                }

                index++;
            }
            if (!deviceFound)
            {
                dmaLog("No PCI devices detected.");
            }
            SetupDiDestroyDeviceInfoList(hDevInfo);
        }

        [DllImport("setupapi.dll", SetLastError = true)]
        static extern IntPtr SetupDiGetClassDevs(IntPtr classGuid, string enumerator, IntPtr hwndParent, uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, int memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true)]
        static extern bool SetupDiGetDeviceRegistryProperty(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData, uint property, out uint propertyRegDataType, StringBuilder propertyBuffer, int propertyBufferSize, out uint requiredSize);

        [DllImport("setupapi.dll", SetLastError = true)]
        static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        [StructLayout(LayoutKind.Sequential)]
        struct SP_DEVINFO_DATA
        {
            public int cbSize;
            public Guid ClassGuid;
            public int DevInst;
            public IntPtr Reserved;
        }

        const uint SPDRP_DEVICEDESC = 0x00000000;
        const uint SPDRP_HARDWAREID = 0x00000001;

    }
}
