using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;

using KeePassLib;

namespace KeePassNatMsg
{
    public partial class AccessControlForm : Form
    {
        public AccessControlForm()
        {
            InitializeComponent();
        }

        private void AllowButton_Click(object sender, EventArgs e)
        {
            Allowed = true;
            Close();
        }

        private void DenyButton_Click(object sender, EventArgs e)
        {
            Denied = true;
            Close();
        }

        // Double-click allows just this entry
        private void EntriesBox_DoubleClick(object sender, EventArgs e)
        {
            var index = EntriesBox.IndexFromPoint(EntriesBox.PointToClient(Cursor.Position));
            if (index == ListBox.NoMatches)
                return;
            // CheckOnClick may still toggle the item afterwards, so remember the entry itself
            _picked = ((EntryItem)EntriesBox.Items[index]).Entry;
            AllowButton_Click(sender, e);
        }

        public bool Allowed = false;
        public bool Denied = false;

        public bool Remember
        {
            get { return RememberCheck.Visible && RememberCheck.Checked; }
        }

        // HTTP Basic Auth asks every time, so there is nothing to remember
        public bool HttpAuth
        {
            set { RememberCheck.Visible = !value; }
        }

        public List<PwEntry> Entries
        {
            set
            {
                Count = value.Count;
                SetLabel();
                foreach (var e in value)
                {
                    if (e == null || e.Strings == null ||
                            e.Strings.Get(PwDefs.TitleField) == null) continue;
                    var title = e.Strings.Get(PwDefs.TitleField).ReadString();
                    if (Plugin == null || Plugin.GetUserPass(e) == null)
                            continue;
                    var username = Plugin.GetUserPass(e)[0];

                    EntriesBox.Items.Add(new EntryItem(e, title + " - " + username), true);
                }
            }
        }

        public List<PwEntry> SelectedEntries
        {
            get
            {
                if (_picked != null)
                    return new List<PwEntry> { _picked };
                return EntriesBox.CheckedItems.Cast<EntryItem>().Select(i => i.Entry).ToList();
            }
        }

        public string Host
        {
            set
            {
                _Host = value;
                SetLabel();
            }
        }

        private void SetLabel()
        {
            if (_Host == null)
                return;
            ConfirmTextLabel.Text = String.Format(
                Message,
                _Host,
                Count == 1 ? "item" : "items",
                Count == 1 ? "Please select whether you want to allow access." :
                    "Allow gives access to the checked items, double-click an item to allow only that one."
            );
        }

        private sealed class EntryItem
        {
            public readonly PwEntry Entry;
            private readonly string _text;

            public EntryItem(PwEntry entry, string text)
            {
                Entry = entry;
                _text = text;
            }

            public override string ToString()
            {
                return _text;
            }
        }

        private PwEntry _picked = null;
        private int Count = 0;
        private const string Message = "{0} has requested access to passwords for the above {1}.\n{2}";
        private string _Host = null;
        internal KeePassNatMsgExt Plugin = null;
    }
}
