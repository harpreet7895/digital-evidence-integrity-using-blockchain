import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st


# -----------------------------
# Configuration
# -----------------------------
LEDGER_FILE = Path(__file__).with_name("blockchain.json")


# -----------------------------
# Digital evidence hashing
# -----------------------------
def calculate_file_hash(file_bytes):
    """Generate the SHA-256 fingerprint of a file."""
    return hashlib.sha256(file_bytes).hexdigest()


# -----------------------------
# Blockchain implementation
# -----------------------------
class Block:
    def __init__(self, index, timestamp, data, previous_hash):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """Hash all important fields in this block."""
        block_content = {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
        }

        encoded = json.dumps(
            block_content,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        return hashlib.sha256(encoded).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }

    @classmethod
    def from_dict(cls, record):
        block = cls(
            index=record["index"],
            timestamp=record["timestamp"],
            data=record["data"],
            previous_hash=record["previous_hash"],
        )
        # Preserve the stored hash so validation can detect tampering.
        block.hash = record["hash"]
        return block


class Blockchain:
    def __init__(self):
        self.chain = []
        self.load_chain()

        if not self.chain:
            self.create_genesis_block()
            self.save_chain()

    def create_genesis_block(self):
        block = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data={"type": "GENESIS", "message": "Evidence ledger created"},
            previous_hash="0",
        )
        self.chain.append(block)

    def add_block(self, data):
        previous_block = self.chain[-1]

        new_block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
            previous_hash=previous_block.hash,
        )

        self.chain.append(new_block)
        self.save_chain()
        return new_block

    def save_chain(self):
        records = [block.to_dict() for block in self.chain]
        temporary_file = LEDGER_FILE.with_suffix(".tmp")
        temporary_file.write_text(
            json.dumps(records, indent=2),
            encoding="utf-8",
        )
        temporary_file.replace(LEDGER_FILE)

    def load_chain(self):
        if not LEDGER_FILE.exists():
            return

        try:
            records = json.loads(
                LEDGER_FILE.read_text(encoding="utf-8")
            )
            self.chain = [Block.from_dict(item) for item in records]
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            st.error(
                "The ledger file could not be loaded. "
                "Keep a backup before repairing or replacing it."
            )
            self.chain = []

    def validate_chain(self):
        """Check block contents and links without changing the ledger."""
        if not self.chain:
            return False, "The ledger is empty."

        for position, block in enumerate(self.chain):
            if block.index != position:
                return False, f"Incorrect block index at position {position}."

            if block.calculate_hash() != block.hash:
                return False, f"Block {position} has been modified."

            if position == 0:
                if block.previous_hash != "0":
                    return False, "Invalid genesis block link."
            else:
                previous_block = self.chain[position - 1]

                if block.previous_hash != previous_block.hash:
                    return False, (
                        f"Broken link between blocks "
                        f"{position - 1} and {position}."
                    )

        return True, "All block hashes and links are valid."


# -----------------------------
# Streamlit application
# -----------------------------
st.set_page_config(
    page_title="Digital Evidence Integrity",
    page_icon="🔐",
    layout="wide",
)

st.title("🔐 Digital Evidence Integrity Using Blockchain")
st.caption(
    "A Python blockchain prototype for registering and verifying "
    "digital forensic evidence."
)

if "blockchain" not in st.session_state:
    st.session_state.blockchain = Blockchain()

ledger = st.session_state.blockchain

register_tab, verify_tab, ledger_tab = st.tabs(
    ["Register Evidence", "Verify Evidence", "Blockchain Ledger"]
)


# -----------------------------
# Register evidence
# -----------------------------
with register_tab:
    st.subheader("Register Digital Evidence")

    with st.form("register_form", clear_on_submit=False):
        evidence_file = st.file_uploader(
            "Choose an evidence file",
            key="register_upload",
        )
        evidence_id = st.text_input(
            "Evidence ID",
            placeholder="e.g. EVD-001",
        )
        description = st.text_area(
            "Evidence description",
            placeholder="Describe the evidence and how it was collected.",
        )
        examiner = st.text_input(
            "Examiner name or identifier",
            placeholder="e.g. Examiner-01",
        )

        submitted = st.form_submit_button("Register Evidence")

    if submitted:
        if evidence_file is None:
            st.error("Please upload an evidence file.")
        elif not evidence_id.strip() or not examiner.strip():
            st.error("Evidence ID and examiner are required.")
        else:
            evidence_id = evidence_id.strip()
            existing_ids = [
                block.data.get("evidence_id")
                for block in ledger.chain
                if block.data.get("type") == "EVIDENCE"
            ]

            if evidence_id in existing_ids:
                st.error("This evidence ID already exists.")
            else:
                file_bytes = evidence_file.getvalue()
                file_hash = calculate_file_hash(file_bytes)

                record = {
                    "type": "EVIDENCE",
                    "evidence_id": evidence_id,
                    "filename": Path(evidence_file.name).name,
                    "file_size_bytes": len(file_bytes),
                    "sha256": file_hash,
                    "description": description.strip(),
                    "examiner": examiner.strip(),
                    "registered_at": datetime.now(
                        timezone.utc
                    ).isoformat(),
                }

                new_block = ledger.add_block(record)

                st.success(
                    f"Evidence {evidence_id} registered successfully!"
                )
                st.write("**Evidence SHA-256:**")
                st.code(file_hash)
                st.write(f"**Blockchain block:** {new_block.index}")
                st.write("**Block hash:**")
                st.code(new_block.hash)
                st.info(
                    "The ledger stores the evidence record and hash, "
                    "not the original evidence file."
                )


# -----------------------------
# Verify evidence
# -----------------------------
with verify_tab:
    st.subheader("Verify Evidence Integrity")

    evidence_blocks = [
        block
        for block in ledger.chain
        if block.data.get("type") == "EVIDENCE"
    ]

    if not evidence_blocks:
        st.info("Register evidence before attempting verification.")
    else:
        evidence_options = {
            (
                f"{block.data['evidence_id']} — "
                f"{block.data['filename']} "
                f"(Block {block.index})"
            ): block
            for block in evidence_blocks
        }

        selected_label = st.selectbox(
            "Select registered evidence",
            list(evidence_options.keys()),
        )
        verification_file = st.file_uploader(
            "Upload the file you want to verify",
            key="verify_upload",
        )

        if st.button("Verify File Integrity"):
            if verification_file is None:
                st.error("Please upload a file for verification.")
            else:
                selected_block = evidence_options[selected_label]
                expected_hash = selected_block.data["sha256"]
                actual_hash = calculate_file_hash(
                    verification_file.getvalue()
                )

                st.write("**Registered SHA-256:**")
                st.code(expected_hash)
                st.write("**Uploaded file SHA-256:**")
                st.code(actual_hash)

                if actual_hash == expected_hash:
                    st.success(
                        "MATCH: The uploaded file has the same "
                        "SHA-256 hash as the registered evidence."
                    )
                else:
                    st.error(
                        "MISMATCH: The file differs from the "
                        "registered evidence or is the wrong file."
                    )

                st.caption(
                    "A match supports file integrity relative to the "
                    "registered hash; it does not independently prove "
                    "who collected the file or when it was collected."
                )


# -----------------------------
# Inspect blockchain ledger
# -----------------------------
with ledger_tab:
    st.subheader("Blockchain Ledger")

    valid, message = ledger.validate_chain()

    if valid:
        st.success(f"Chain validation passed: {message}")
    else:
        st.error(f"Chain validation failed: {message}")

    st.write(f"**Total blocks:** {len(ledger.chain)}")

    for block in reversed(ledger.chain):
        with st.expander(
            f"Block {block.index} — {block.timestamp}"
        ):
            st.json(block.to_dict())

    st.info(
    "Project Note: This system demonstrates blockchain-based "
    "digital evidence integrity using SHA-256 hashing and "
    "hash-linked blocks. Further development can include "
    "distributed validation and access control."
)
    
