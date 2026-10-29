using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows.Forms;

namespace KeePassNatMsg.NativeMessaging
{
    [Flags]
    public enum Browsers
    {
        None,

        [Description("Google Chrome")]
        Chrome,

        Chromium,
        Firefox = 4,
        Vivaldi = 8,

        [Description("Microsoft Edge")]
        Edge = 16,
        Thunderbird = 32,
    }

    public enum BrowserStatus
    {
        [Description("Not Installed")]
        NotInstalled,
        Detected,
        Installed
    }

    public abstract class NativeMessagingHost
    {
        protected const string NmhKey = "NativeMessagingHosts";
        protected const string ProxyExecutable = "keepassnatmsg-proxy.exe";
        private const string ExtKeyBrowser = "org.keepassxc.keepassxc_browser";
        private const string ExtKeyThunderbird = "de.kkapsner.keepassxc_mail";

        protected Encoding _utf8 = new UTF8Encoding(false);

        public Form ParentForm { get; set; }
        public string ProxyExePath
        {
            get
            {
                return Path.Combine(ProxyPath, ProxyExecutable);
            }
        }

        public static NativeMessagingHost GetHost()
        {
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    return new WindowsHost();
                case PlatformID.Unix:
                    return new LinuxHost();
                case PlatformID.MacOSX:
                    return new MacOsxHost();
                default:
                    throw new PlatformNotSupportedException(string.Format("{0} is not a supported platform.", Environment.OSVersion.Platform));
            }
        }

        protected string GetJsonData(Browsers b)
        {
            switch (b)
            {
                case Browsers.Chrome:
                case Browsers.Chromium:
                case Browsers.Vivaldi:
                    return Properties.Resources.chrome_json;
                case Browsers.Firefox:
                    return Properties.Resources.firefox_json;
                case Browsers.Edge:
                    return Properties.Resources.edge_json;
                case Browsers.Thunderbird:
                    return Properties.Resources.thunderbird_json;
            }
            return null;
        }

        public Version GetProxyVersion()
        {
            if (File.Exists(ProxyExePath))
            {
                var fvi = System.Diagnostics.FileVersionInfo.GetVersionInfo(ProxyExePath);
                Version exeVer;
                if (Version.TryParse(fvi.FileVersion, out exeVer))
                {
                    return exeVer;
                }
            }
            return null;
        }

        // The proxy is embedded into the plugin, see KeePassNatMsg.Proxy
        private static byte[] GetEmbeddedProxy()
        {
            var assembly = typeof(NativeMessagingHost).Assembly;
            var name = Array.Find(assembly.GetManifestResourceNames(), n => n.EndsWith(ProxyExecutable, StringComparison.OrdinalIgnoreCase));
            using (var stream = assembly.GetManifestResourceStream(name))
            using (var ms = new MemoryStream())
            {
                stream.CopyTo(ms);
                return ms.ToArray();
            }
        }

        public bool IsProxyUpToDate()
        {
            return File.Exists(ProxyExePath) && StructuralComparisons.StructuralEqualityComparer.Equals(File.ReadAllBytes(ProxyExePath), GetEmbeddedProxy());
        }

        public bool UpdateProxy()
        {
            try
            {
                if (!IsProxyUpToDate())
                {
                    Directory.CreateDirectory(ProxyPath);
                    File.WriteAllBytes(ProxyExePath, GetEmbeddedProxy());
                }

                return true;
            }
            catch (Exception ex)
            {
                MessageBox.Show(ParentForm, "An error occurred attempting to install the proxy application. If a browser is running, close it and try again.\n\n" + ex, "Proxy Install Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            return false;
        }

        protected string GetExtKey(Browsers b)
        {
            switch(b)
            {
                case Browsers.Thunderbird:
                    return ExtKeyThunderbird;
                default:
                    return ExtKeyBrowser;
            }
        }

        public abstract string ProxyPath { get; }
        public abstract void Install(Browsers browsers);
        public abstract Dictionary<Browsers, BrowserStatus> GetBrowserStatuses();
    }
}
