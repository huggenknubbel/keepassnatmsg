using KeePassLib;
using KeePassLib.Collections;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

namespace KeePassNatMsg.Passkeys
{
    /// <summary>
    /// Confirms a passkey registration or authentication.
    /// DialogResult.OK registers a new entry or authenticates with the selected entry,
    /// DialogResult.Yes stores the new passkey in the selected entry.
    /// </summary>
    internal sealed class PasskeyConfirmationForm : Form
    {
        private readonly Label _label = new Label { Dock = DockStyle.Top, AutoSize = true, Padding = new Padding(0, 0, 0, 8) };
        private readonly TextBox _search = new TextBox { Dock = DockStyle.Top, Visible = false };
        private readonly ListView _list = new ListView
        {
            Dock = DockStyle.Fill,
            View = View.Details,
            FullRowSelect = true,
            MultiSelect = false,
            HideSelection = false,
        };
        private readonly ProgressBar _progress = new ProgressBar { Dock = DockStyle.Bottom, Height = 12 };
        private readonly Label _timeoutLabel = new Label { Dock = DockStyle.Bottom, AutoSize = true, Padding = new Padding(0, 4, 0, 4) };
        private readonly Button _confirmButton = new Button { AutoSize = true, DialogResult = DialogResult.OK };
        private readonly Button _entryButton = new Button { AutoSize = true, DialogResult = DialogResult.Yes, Visible = false };
        private readonly Button _cancelButton = new Button { AutoSize = true, Text = "Cancel", DialogResult = DialogResult.Cancel };
        private readonly Timer _timer = new Timer { Interval = 1000 };

        private List<PwEntryDatabase> _initialEntries;
        private List<PwDatabase> _databases;
        private bool _register;
        private bool _hasPasskeyEntries;
        private int _secondsLeft;

        public PwEntryDatabase SelectedEntry
        {
            get { return _list.SelectedItems.Count > 0 ? (PwEntryDatabase)_list.SelectedItems[0].Tag : null; }
        }

        public PasskeyConfirmationForm()
        {
            Text = "KeePassNatMsg - Passkey";
            ClientSize = new Size(480, 340);
            MinimumSize = new Size(360, 260);
            Padding = new Padding(10);
            TopMost = true;
            ShowInTaskbar = false;
            MinimizeBox = false;
            MaximizeBox = false;
            AcceptButton = _confirmButton;
            CancelButton = _cancelButton;

            _list.Columns.Add("Title", 180);
            _list.Columns.Add("Username", 150);
            _list.Columns.Add("Group", 110);

            var buttons = new FlowLayoutPanel
            {
                Dock = DockStyle.Bottom,
                FlowDirection = FlowDirection.RightToLeft,
                AutoSize = true,
                Padding = new Padding(0, 8, 0, 0),
            };
            buttons.Controls.AddRange(new Control[] { _cancelButton, _confirmButton, _entryButton });

            Controls.Add(_list);
            Controls.Add(_search);
            Controls.Add(_label);
            Controls.Add(_timeoutLabel);
            Controls.Add(_progress);
            Controls.Add(buttons);

            _search.TextChanged += delegate { Search(); };
            _search.KeyDown += OnSearchKeyDown;
            _list.SelectedIndexChanged += delegate { UpdateButtons(); };
            _list.DoubleClick += OnListDoubleClick;
            _timer.Tick += OnTimerTick;
        }

        public void SetRegister(string username, string rpId, List<PwEntryDatabase> existingEntries, List<PwEntryDatabase> suggestedEntries, List<PwDatabase> databases, int timeout)
        {
            _databases = databases;
            _register = true;
            _hasPasskeyEntries = existingEntries.Count > 0;
            _search.Visible = true;
            _entryButton.Visible = true;
            _confirmButton.Text = "Register new";

            string hint;
            if (_hasPasskeyEntries)
            {
                hint = "Existing passkey found. Select it and press Update to replace it,\nor search for another entry.";
                _entryButton.Text = "Update";
                _initialEntries = existingEntries;
            }
            else
            {
                hint = suggestedEntries.Count > 0
                    ? "Matching entries without a passkey were found. Select one and press\nAdd to entry, or search for another entry."
                    : "Search for an entry to add the passkey to, or register a new entry.";
                _entryButton.Text = "Add to entry";
                _initialEntries = suggestedEntries;
            }

            _label.Text = string.Format("Do you want to register a passkey for:\n\nRelying Party: {0}\nUsername: {1}\n\n{2}", rpId, username, hint);
            ShowEntries(_initialEntries);
            StartTimer(timeout);
        }

        public void SetAuthenticate(string rpId, List<PwEntryDatabase> entries, int timeout)
        {
            _hasPasskeyEntries = true;
            _confirmButton.Text = "Authenticate";
            _label.Text = string.Format("Authenticate passkey credentials for:\n\nRelying Party: {0}", rpId);
            _initialEntries = entries;
            ShowEntries(entries);
            StartTimer(timeout);
        }

        protected override void OnShown(EventArgs e)
        {
            base.OnShown(e);
            if (_register)
                _search.Focus();
            else
                _list.Focus();
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            _timer.Stop();
            base.OnFormClosed(e);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                _timer.Dispose();
            base.Dispose(disposing);
        }

        // Searches all entries of the databases with KeePass' own search syntax
        private void Search()
        {
            var text = _search.Text.Trim();
            if (text.Length == 0)
            {
                ShowEntries(_initialEntries);
                return;
            }

            var parameters = new SearchParameters
            {
                SearchString = text,
                SearchInTitles = true,
                SearchInUserNames = true,
                SearchInUrls = true,
                SearchInNotes = false,
                SearchInPasswords = false,
                SearchInOther = false,
                SearchInTags = true,
                ComparisonMode = StringComparison.InvariantCultureIgnoreCase,
            };

            var results = new List<PwEntryDatabase>();
            foreach (var db in _databases)
            {
                var found = new PwObjectList<PwEntry>();
                db.RootGroup.SearchEntries(parameters, found);
                results.AddRange(found.Select(entry => new PwEntryDatabase(entry, db)));
            }
            ShowEntries(results);
        }

        private void ShowEntries(List<PwEntryDatabase> entries)
        {
            _list.BeginUpdate();
            _list.Items.Clear();
            foreach (var e in entries)
            {
                var username = PasskeyHandler.HasPasskey(e.entry) ? PasskeyHandler.GetPasskeyUsername(e.entry) : e.entry.Strings.ReadSafe(PwDefs.UserNameField);
                var item = new ListViewItem(new[]
                {
                    e.entry.Strings.ReadSafe(PwDefs.TitleField),
                    username,
                    e.entry.ParentGroup == null ? string.Empty : e.entry.ParentGroup.Name,
                }) { Tag = e };
                _list.Items.Add(item);
            }
            if (_list.Items.Count > 0)
                _list.Items[0].Selected = true;
            _list.EndUpdate();
            UpdateButtons();
        }

        private void UpdateButtons()
        {
            var hasSelection = _list.SelectedItems.Count > 0;
            _entryButton.Enabled = hasSelection;
            if (!_register)
                _confirmButton.Enabled = hasSelection;

            // Enter adds the passkey to a selected suggestion, otherwise it registers a new entry
            AcceptButton = _register && hasSelection && (!_hasPasskeyEntries || _search.Text.Length > 0) ? _entryButton : _confirmButton;
        }

        private void OnSearchKeyDown(object sender, KeyEventArgs e)
        {
            if ((e.KeyCode != Keys.Down && e.KeyCode != Keys.Up) || _list.Items.Count == 0)
                return;

            var index = _list.SelectedIndices.Count > 0 ? _list.SelectedIndices[0] : -1;
            index = Math.Max(0, Math.Min(_list.Items.Count - 1, index + (e.KeyCode == Keys.Down ? 1 : -1)));
            _list.Items[index].Selected = true;
            _list.EnsureVisible(index);
            e.Handled = true;
        }

        private void OnListDoubleClick(object sender, EventArgs e)
        {
            if (SelectedEntry == null)
                return;
            DialogResult = AcceptButton == _entryButton ? DialogResult.Yes : DialogResult.OK;
        }

        private void StartTimer(int timeout)
        {
            _secondsLeft = Math.Max(1, timeout / 1000);
            _progress.Maximum = _secondsLeft;
            UpdateTimeout();
            _timer.Start();
        }

        private void OnTimerTick(object sender, EventArgs e)
        {
            _secondsLeft--;
            if (_secondsLeft <= 0)
            {
                DialogResult = DialogResult.Cancel;
                return;
            }
            UpdateTimeout();
        }

        private void UpdateTimeout()
        {
            _progress.Value = _secondsLeft;
            _timeoutLabel.Text = string.Format("Timeout in {0} seconds...", _secondsLeft);
        }
    }
}
