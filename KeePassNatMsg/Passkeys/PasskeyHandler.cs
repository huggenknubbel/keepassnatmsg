using KeePass.Plugins;
using KeePassLib;
using KeePassLib.Collections;
using KeePassLib.Security;
using KeePassNatMsg.Entry;
using KeePassNatMsg.Protocol;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Forms;

namespace KeePassNatMsg.Passkeys
{
    /// <summary>
    /// Handles passkeys-register and passkeys-get. Passkeys are stored in the same
    /// KPEX_PASSKEY_* string fields as KeePassXC uses.
    /// </summary>
    public sealed class PasskeyHandler
    {
        public const string PasskeyAttribute = "KPEX_PASSKEY";
        public const string UsernameField = "KPEX_PASSKEY_USERNAME";
        public const string CredentialIdField = "KPEX_PASSKEY_CREDENTIAL_ID";
        public const string PrivateKeyPemField = "KPEX_PASSKEY_PRIVATE_KEY_PEM";
        public const string RelyingPartyField = "KPEX_PASSKEY_RELYING_PARTY";
        public const string UserHandleField = "KPEX_PASSKEY_USER_HANDLE";
        public const string FlagBEField = "KPEX_PASSKEY_FLAG_BE";
        public const string FlagBSField = "KPEX_PASSKEY_FLAG_BS";

        // Written by StrongBox
        private const string GeneratedUserIdField = "KPEX_PASSKEY_GENERATED_USER_ID";
        private const string KpxcUsernameField = "KPXC_PASSKEY_USERNAME";

        private const string DefaultGroupName = "KeePassXC-Browser Passkeys";
        private const string PasskeyTag = "Passkey";
        private const int DefaultTimeout = 300000;

        private readonly IPluginHost _host;
        private readonly KeePassNatMsgExt _ext;

        public PasskeyHandler()
        {
            _host = KeePassNatMsgExt.HostInstance;
            _ext = KeePassNatMsgExt.ExtInstance;
        }

        public JObject Register(JObject publicKey, string origin, string groupName)
        {
            CredentialCreationOptions options;
            var error = PasskeyOptions.GetCredentialCreationOptions(publicKey, origin, out options);
            if (error != 0)
                return GetError(error);

            var passkeyEntries = GetPasskeyEntries(options.RpId);
            var excludedIds = options.ExcludeCredentials.OfType<JObject>().Select(c => (string)c["id"]).ToList();
            if (passkeyEntries.Any(e => excludedIds.Contains(GetCredentialId(e.entry))))
                return GetError(ErrorType.PasskeysCredentialIsExcluded);

            var existingEntries = passkeyEntries.Where(e => e.entry.Strings.ReadSafe(UserHandleField) == options.UserId).ToList();
            var suggestedEntries = existingEntries.Count == 0
                ? new EntrySearch().FindMatchingEntries(origin, null).Where(e => !HasPasskey(e.entry)).ToList()
                : new List<PwEntryDatabase>();

            var result = DialogResult.Cancel;
            PwEntryDatabase selected = null;
            Invoke(() =>
            {
                using (var f = new PasskeyConfirmationForm())
                {
                    f.SetRegister(options.UserName, options.RpId, existingEntries, suggestedEntries, _ext.GetSearchDatabases(), GetTimeout(publicKey));
                    result = ShowDialog(f);
                    selected = f.SelectedEntry;
                }
            });

            if (result == DialogResult.Cancel || (result == DialogResult.Yes && selected == null))
                return GetError(ErrorType.PasskeysRequestCanceled);

            var credential = PasskeyCrypto.BuildRegisterCredential(options);

            var saved = false;
            Invoke(() =>
            {
                saved = result == DialogResult.Yes
                    ? AddPasskeyToEntry(selected.entry, selected.database, options, credential)
                    : AddPasskeyToGroup(options, credential, groupName);
            });

            return saved ? credential.Response : GetError(ErrorType.PasskeysRequestCanceled);
        }

        public JObject Authenticate(JObject publicKey, string origin)
        {
            AssertionOptions options;
            var error = PasskeyOptions.GetAssertionOptions(publicKey, origin, out options);
            if (error != 0)
                return GetError(error);

            var entries = GetAllowedEntries(options);
            if (entries.Count == 0)
                return GetError(ErrorType.NoLoginsFound);

            var result = DialogResult.Cancel;
            PwEntryDatabase selected = null;
            Invoke(() =>
            {
                using (var f = new PasskeyConfirmationForm())
                {
                    f.SetAuthenticate(options.RpId, entries, GetTimeout(publicKey));
                    result = ShowDialog(f);
                    selected = f.SelectedEntry;
                }
            });

            if (result != DialogResult.OK || selected == null)
                return GetError(ErrorType.PasskeysRequestCanceled);

            var strings = selected.entry.Strings;
            var response = PasskeyCrypto.BuildGetCredential(options,
                GetCredentialId(selected.entry),
                strings.ReadSafe(UserHandleField),
                strings.ReadSafe(PrivateKeyPemField),
                GetFlag(strings, FlagBEField),
                GetFlag(strings, FlagBSField));

            return response ?? GetError(ErrorType.PasskeysUnknownError);
        }

        public static bool HasPasskey(PwEntry entry)
        {
            return entry.Strings.Any(s => s.Key.StartsWith(PasskeyAttribute, StringComparison.Ordinal));
        }

        public static string GetPasskeyUsername(PwEntry entry)
        {
            return entry.Strings.Exists(KpxcUsernameField) ? entry.Strings.ReadSafe(KpxcUsernameField) : entry.Strings.ReadSafe(UsernameField);
        }

        private static string GetCredentialId(PwEntry entry)
        {
            return entry.Strings.Exists(GeneratedUserIdField) ? entry.Strings.ReadSafe(GeneratedUserIdField) : entry.Strings.ReadSafe(CredentialIdField);
        }

        private static bool GetFlag(ProtectedStringDictionary strings, string field)
        {
            if (!strings.Exists(field))
                return true;
            var value = strings.ReadSafe(field);
            return value == "1" || value.Equals("true", StringComparison.OrdinalIgnoreCase);
        }

        private static int GetTimeout(JObject publicKey)
        {
            var timeout = publicKey["timeout"];
            return timeout != null && timeout.Type == JTokenType.Integer && (int)timeout > 0 ? (int)timeout : DefaultTimeout;
        }

        private static JObject GetError(ErrorType error)
        {
            return new JObject { { "errorCode", (int)error } };
        }

        private List<PwEntryDatabase> GetPasskeyEntries(string rpId)
        {
            return _ext.GetSearchDatabases()
                .SelectMany(db => db.RootGroup.GetEntries(true).Select(e => new PwEntryDatabase(e, db)))
                .Where(e => HasPasskey(e.entry) && e.entry.Strings.ReadSafe(RelyingPartyField) == rpId)
                .ToList();
        }

        // Without allowCredentials, any passkey with a user handle (discoverable credential) can be used
        private List<PwEntryDatabase> GetAllowedEntries(AssertionOptions options)
        {
            var allowed = options.AllowCredentials.OfType<JObject>()
                .Where(c => (string)c["type"] == PasskeyOptions.PublicKeyType && !string.IsNullOrEmpty((string)c["id"]))
                .Where(c =>
                {
                    var transports = c["transports"] as JArray;
                    return transports == null || transports.Count == 0
                        || transports.Any(t => (string)t == "internal" || (string)t == "nfc" || (string)t == "usb");
                })
                .Select(c => (string)c["id"])
                .ToList();

            if (options.AllowCredentials.Count > 0 && allowed.Count == 0)
                return new List<PwEntryDatabase>();

            return GetPasskeyEntries(options.RpId)
                .Where(e => allowed.Contains(GetCredentialId(e.entry)) || (allowed.Count == 0 && e.entry.Strings.Exists(UserHandleField)))
                .ToList();
        }

        private bool AddPasskeyToEntry(PwEntry entry, PwDatabase db, CredentialCreationOptions options, RegisteredCredential credential)
        {
            if (HasPasskey(entry))
            {
                var answer = MessageBox.Show(_host.MainWindow,
                    string.Format("Entry already has a passkey.\nDo you want to overwrite the passkey in {0} - {1}?",
                        entry.Strings.ReadSafe(PwDefs.TitleField), GetPasskeyUsername(entry)),
                    "Update passkey", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2);
                if (answer != DialogResult.Yes)
                    return false;
            }

            entry.History = entry.History.CloneDeep();
            entry.CreateBackup(db);
            SetPasskey(entry, options, credential);
            entry.Touch(true, false);

            _ext.UpdateUI(entry.ParentGroup);
            EntryUpdate.AutoSaveIfRequired(db);
            return true;
        }

        private bool AddPasskeyToGroup(CredentialCreationOptions options, RegisteredCredential credential, string groupName)
        {
            var db = _ext.GetConnectionDatabase();
            var group = db.RootGroup.FindCreateSubTree(string.IsNullOrEmpty(groupName) ? DefaultGroupName : groupName, new[] { '/' }, true);
            if (group == null)
                return false;

            var entry = new PwEntry(true, true) { IconId = PwIcon.MultiKeys };
            entry.Strings.Set(PwDefs.TitleField, new ProtectedString(false, string.Format("{0} (Passkey)", options.RpName)));
            entry.Strings.Set(PwDefs.UserNameField, new ProtectedString(false, options.UserName ?? string.Empty));
            entry.Strings.Set(PwDefs.UrlField, new ProtectedString(false, options.Origin));
            SetPasskey(entry, options, credential);
            group.AddEntry(entry, true);

            _ext.UpdateUI(group);
            EntryUpdate.AutoSaveIfRequired(db);
            return true;
        }

        private static void SetPasskey(PwEntry entry, CredentialCreationOptions options, RegisteredCredential credential)
        {
            entry.Strings.Set(UsernameField, new ProtectedString(false, options.UserName ?? string.Empty));
            entry.Strings.Set(CredentialIdField, new ProtectedString(true, credential.CredentialId));
            entry.Strings.Set(PrivateKeyPemField, new ProtectedString(true, credential.PrivateKeyPem));
            entry.Strings.Set(RelyingPartyField, new ProtectedString(false, options.RpId));
            entry.Strings.Set(UserHandleField, new ProtectedString(true, options.UserId));
            entry.Strings.Set(FlagBEField, new ProtectedString(false, "1"));
            entry.Strings.Set(FlagBSField, new ProtectedString(false, "1"));
            entry.AddTag(PasskeyTag);
        }

        private DialogResult ShowDialog(Form f)
        {
            var win = _host.MainWindow;
            f.Icon = win.Icon;
            f.StartPosition = win.Visible ? FormStartPosition.CenterParent : FormStartPosition.CenterScreen;
            f.Load += delegate { f.Activate(); };
            return f.ShowDialog(win);
        }

        private void Invoke(System.Action action)
        {
            _host.MainWindow.Invoke(action);
        }
    }
}
