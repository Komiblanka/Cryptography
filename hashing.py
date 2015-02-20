from Crypto.Hash import SHA256

message_to_hash = raw_input("Enter the message to hash with SHA256: ")
print SHA256.new(message_to_hash).hexdigest()
