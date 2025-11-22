# Delta-Spark Smart Contract

## Description

Delta-Spark is a privacy-preserving identity verification smart contract built on Stacks blockchain using Clarity. The contract enables users to create temporal identity fragments (time-locked cryptographic proofs) for various attributes without revealing the underlying data. It implements a comprehensive reputation system with anonymous endorsements, oracle validation, and fragment verification capabilities.

The contract provides a decentralized framework for managing identity proofs with built-in expiration, revocation mechanisms, and reputation scoring. Users can prove specific attributes about themselves while maintaining complete privacy, and the system supports a distributed oracle network for external validation of identity fragments.

## Features

- **Temporal Identity Fragments**: Create time-locked identity proofs that automatically expire after a specified number of blocks
- **Privacy-Preserving Verification**: Verify identity attributes using cryptographic proof hashes without revealing underlying data
- **Reputation System**: Track user reputation scores based on verified fragments and endorsements
- **Anonymous Endorsements**: Allow verified users to endorse others without revealing their identities using cryptographic hashes
- **Oracle Network**: Support for distributed oracle validators to validate identity fragments
- **Attribute Type Registry**: Configurable attribute types with reputation requirements and verification settings
- **Revocation Mechanism**: Users can instantly revoke their identity fragments
- **Fragment Expiration**: Automatic expiration of identity proofs based on block height
- **Verification Tracking**: Complete audit trail of all verifications with scores and timestamps
- **Platform Statistics**: Real-time tracking of total proofs, verifications, and oracle activity

## Contract Functions

### Public Functions

#### `initialize-identity`
Creates a new user identity record with zero reputation and fragment count.
- **Parameters**: None
- **Returns**: `(ok true)` on success, `ERR-ALREADY-EXISTS` if identity exists
- **Usage**: Must be called before creating identity fragments

#### `create-identity-fragment`
Creates a new temporal identity fragment with specified attribute type and expiration.
- **Parameters**:
  - `attribute-type (string-ascii 50)`: Type of attribute being proven
  - `proof-hash (buff 32)`: Cryptographic hash of the proof
  - `validity-blocks (uint)`: Number of blocks until expiration
- **Returns**: `(ok fragment-id)` on success
- **Requires**: User identity must exist, attribute type must be enabled

#### `verify-fragment`
Verifies an identity fragment and updates reputation scores.
- **Parameters**:
  - `fragment-id (uint)`: ID of fragment to verify
  - `attribute-confirmed (bool)`: Whether verification passed
  - `verification-score (uint)`: Score to add to reputation
- **Returns**: `(ok proof-id)` on success
- **Requires**: Fragment must be valid (not expired, not revoked)

#### `revoke-fragment`
Revokes an identity fragment, making it invalid for future verifications.
- **Parameters**:
  - `fragment-id (uint)`: ID of fragment to revoke
- **Returns**: `(ok true)` on success
- **Requires**: Caller must be fragment owner

#### `create-endorsement`
Creates an anonymous endorsement for another user, boosting their reputation.
- **Parameters**:
  - `endorsed-user (principal)`: User being endorsed
  - `attribute-type (string-ascii 50)`: Type of attribute endorsed
  - `endorser-hash (buff 32)`: Cryptographic hash of endorser identity
  - `weight (uint)`: Reputation weight of endorsement
- **Returns**: `(ok endorsement-id)` on success
- **Requires**: Endorser must have reputation >= 50, both users must have identities

#### `register-oracle`
Registers a new oracle validator in the network (owner only).
- **Parameters**:
  - `oracle-address (principal)`: Address of oracle to register
- **Returns**: `(ok oracle-id)` on success
- **Requires**: Caller must be contract owner

#### `deactivate-oracle`
Deactivates an oracle validator (owner only).
- **Parameters**:
  - `oracle-id (uint)`: ID of oracle to deactivate
- **Returns**: `(ok true)` on success
- **Requires**: Caller must be contract owner

#### `oracle-validate-fragment`
Allows registered oracles to validate identity fragments.
- **Parameters**:
  - `oracle-id (uint)`: ID of calling oracle
  - `fragment-id (uint)`: Fragment to validate
  - `validation-score (uint)`: Reputation score to add
- **Returns**: `(ok true)` on success
- **Requires**: Oracle must be active, caller must be registered oracle address

#### `register-attribute-type`
Registers a new attribute type (owner only).
- **Parameters**:
  - `attribute-name (string-ascii 50)`: Name of attribute type
  - `min-reputation (uint)`: Minimum reputation required
  - `verification-required (bool)`: Whether verification is required
- **Returns**: `(ok true)` on success
- **Requires**: Caller must be contract owner

#### `disable-attribute-type`
Disables an existing attribute type (owner only).
- **Parameters**:
  - `attribute-name (string-ascii 50)`: Name of attribute type to disable
- **Returns**: `(ok true)` on success
- **Requires**: Caller must be contract owner

#### `update-platform-fee`
Updates the platform fee (owner only).
- **Parameters**:
  - `new-fee (uint)`: New fee in micro-STX
- **Returns**: `(ok true)` on success
- **Requires**: Caller must be contract owner

### Read-Only Functions

#### `get-identity-fragment`
Retrieves identity fragment details by ID.
- **Parameters**: `fragment-id (uint)`
- **Returns**: Fragment data or `none`

#### `get-user-identity`
Retrieves user identity information.
- **Parameters**: `user (principal)`
- **Returns**: User identity data or `none`

#### `get-proof-verification`
Retrieves proof verification record.
- **Parameters**: `proof-id (uint)`
- **Returns**: Verification data or `none`

#### `get-oracle-info`
Retrieves oracle information.
- **Parameters**: `oracle-id (uint)`
- **Returns**: Oracle data or `none`

#### `get-endorsement`
Retrieves endorsement details.
- **Parameters**: `endorsement-id (uint)`
- **Returns**: Endorsement data or `none`

#### `is-fragment-valid`
Checks if a fragment is valid (not expired and not revoked).
- **Parameters**: `fragment-id (uint)`
- **Returns**: `true` if valid, `false` otherwise

#### `is-attribute-enabled`
Checks if an attribute type is enabled.
- **Parameters**: `attribute-name (string-ascii 50)`
- **Returns**: `true` if enabled, `false` otherwise

#### `get-platform-stats`
Retrieves platform-wide statistics.
- **Parameters**: None
- **Returns**: Object with total-proofs, total-verifications, oracle-count, platform-fee

