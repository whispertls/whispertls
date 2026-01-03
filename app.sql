CREATE TABLE networks (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL
);

INSERT INTO networks (id,name) VALUES (1,'TOR');
INSERT INTO networks (id,name) VALUES (2,'I2P');

CREATE TABLE contacts (
    id TEXT PRIMARY KEY, -- 64bit hexadecimal string
    nickname TEXT NOT NULL DEFAULT ''
);

CREATE TABLE oob_verification (
	contact_id TEXT NOT NULL,
	verification_code TEXT NOT NULL,
	FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
	UNIQUE(contact_id)
);

CREATE TABLE contacts_bundles (
    contact_id TEXT NOT NULL,
	network_type INTEGER NOT NULL,
	network_address TEXT NOT NULL,
	tls_cert_pem BLOB NOT NULL,
    public_bytes BLOB NOT NULL,
	FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE,
	UNIQUE(contact_id)
);

CREATE TABLE identities (
    contact_id TEXT NOT NULL,
	purpose INTEGER NOT NULL,       -- 1 REGULAR CONTACT , 2 OOB
	network_address TEXT NOT NULL,  -- TOR addrress without .onion
	network_key TEXT NOT NULL,	    -- format is base64
	network_type INTEGER NOT NULL,  -- 1 TOR, 2 I2P
	tls_cert_pem BLOB NOT NULL,
    tls_key_pem BLOB NOT NULL,
	tls_key_password TEXT NOT NULL,
    private_bytes BLOB NOT NULL,    -- ed25519
    public_bytes BLOB NOT NULL,     -- ed25519
	ratchet_password BLOB NOT NULL, -- for double ratchet database
	is_ready INTEGER NOT NULL default 0, 
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, --Internal ID, we should make some gaps between
	display_id TEXT NOT NULL,	-- Random Application ID
    contact_id TEXT NOT NULL,
    message BLOB NOT NULL,		-- Internal data of the message, format depends of UI Logic and message type
    message_type TEXT NOT NULL, -- text!, file*, img*, stiker*, 
	direction INTEGER NOT NULL, -- 1 - from contact_id , 2 - to contact_id
	is_sent  INTEGER NOT NULL default 0, -- only confirms that was send by current applicatio
	is_received  INTEGER NOT NULL default 0, -- this is only a confirmation that was received from remote Application, is not a read receipts
	is_readed  INTEGER NOT NULL default 0, -- read receipts are dissabled by default... 
	send_queue INTEGER NOT NULL default 0, -- those are flags to now if the current message was taken for specific_queue / process
	receive_queue INTEGER NOT NULL default 0,
	read_queue INTEGER NOT NULL default 0,
    FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
);

CREATE TABLE config (
    config_key TEXT PRIMARY KEY,
    config_value TEXT NOT NULL DEFAULT ''
);

INSERT INTO config (config_key,config_value) values ('core_certificate_minutes','10080'); -- 1 week
INSERT INTO config (config_key,config_value) values ('core_interval_seconds','15');
INSERT INTO config (config_key,config_value) values ('core_timeout_seconds','300'); --5 minutes
INSERT INTO config (config_key,config_value) values ('core_fixed_message_size_KiB','2');
INSERT INTO config (config_key,config_value) values ('tor_address','127.0.0.1');
INSERT INTO config (config_key,config_value) values ('tor_port','9050');
INSERT INTO config (config_key,config_value) values ('tor_controlport','9051');
INSERT INTO config (config_key,config_value) values ('tor_password','');
INSERT INTO config (config_key,config_value) values ('messages_read_receipts','disabled');
INSERT INTO config (config_key,config_value) values ('messages_send_timestamp','disabled');
INSERT INTO config (config_key,config_value) values ('messages_download_path','./downloads');
INSERT INTO config (config_key,config_value) values ('finish','1');
