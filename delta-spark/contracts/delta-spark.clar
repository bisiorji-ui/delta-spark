;; Delta-Spark - Zero-Knowledge Identity Verification System
;; A privacy-preserving identity verification platform using cryptographic proofs

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-INVALID-PROOF (err u101))
(define-constant ERR-PROOF-EXPIRED (err u102))
(define-constant ERR-IDENTITY-NOT-FOUND (err u103))
(define-constant ERR-ALREADY-EXISTS (err u104))
(define-constant ERR-INVALID-ATTRIBUTE (err u105))
(define-constant ERR-REPUTATION-TOO-LOW (err u106))
(define-constant ERR-ORACLE-NOT-FOUND (err u107))
(define-constant ERR-INSUFFICIENT-ENDORSEMENTS (err u108))
(define-constant ERR-FRAGMENT-REVOKED (err u109))
(define-constant ERR-INVALID-TIMESTAMP (err u110))

;; Minimum reputation score required for certain operations
(define-constant MIN-REPUTATION-SCORE u50)
(define-constant MIN-ENDORSEMENTS u3)
(define-constant PROOF-VALIDITY-PERIOD u144) ;; approximately 1 day in blocks

;; Data Variables
(define-data-var platform-fee uint u100) ;; Fee in micro-STX
(define-data-var oracle-count uint u0)
(define-data-var total-proofs-generated uint u0)
(define-data-var total-verifications uint u0)

;; Identity Fragment Structure
;; Represents a time-locked identity proof
(define-map identity-fragments
    { fragment-id: uint }
    {
        owner: principal,
        attribute-type: (string-ascii 50),
        proof-hash: (buff 32),
        created-at: uint,
        expires-at: uint,
        revoked: bool,
        verification-count: uint,
        reputation-score: uint
    }
)

;; User Identity Registry
(define-map user-identities
    { user: principal }
    {
        total-fragments: uint,
        reputation-score: uint,
        endorsement-count: uint,
        created-at: uint,
        last-activity: uint
    }
)

;; Attribute Proof Verification Records
(define-map proof-verifications
    { proof-id: uint }
    {
        fragment-id: uint,
        verifier: principal,
        verified-at: uint,
        attribute-confirmed: bool,
        verification-score: uint
    }
)

;; Oracle Network Registry
(define-map oracle-registry
    { oracle-id: uint }
    {
        oracle-address: principal,
        reputation: uint,
        total-validations: uint,
        active: bool,
        registered-at: uint
    }
)

;; Anonymous Endorsements
(define-map endorsements
    { endorsement-id: uint }
    {
        endorser-hash: (buff 32), ;; Hash of endorser identity for anonymity
        endorsed-user: principal,
        attribute-type: (string-ascii 50),
        weight: uint,
        timestamp: uint
    }
)

;; Attribute Type Registry
(define-map attribute-types
    { attribute-name: (string-ascii 50) }
    {
        enabled: bool,
        min-reputation: uint,
        verification-required: bool
    }
)

;; Fragment ID counter
(define-data-var fragment-counter uint u0)
(define-data-var proof-counter uint u0)
(define-data-var endorsement-counter uint u0)

;; Read-only functions

;; Get identity fragment details
(define-read-only (get-identity-fragment (fragment-id uint))
    (map-get? identity-fragments { fragment-id: fragment-id })
)

;; Get user identity information
(define-read-only (get-user-identity (user principal))
    (map-get? user-identities { user: user })
)

;; Get proof verification record
(define-read-only (get-proof-verification (proof-id uint))
    (map-get? proof-verifications { proof-id: proof-id })
)

;; Get oracle information
(define-read-only (get-oracle-info (oracle-id uint))
    (map-get? oracle-registry { oracle-id: oracle-id })
)

;; Get endorsement details
(define-read-only (get-endorsement (endorsement-id uint))
    (map-get? endorsements { endorsement-id: endorsement-id })
)

;; Check if fragment is valid (not expired and not revoked)
(define-read-only (is-fragment-valid (fragment-id uint))
    (match (get-identity-fragment fragment-id)
        fragment
        (and
            (not (get revoked fragment))
            (< stacks-block-height (get expires-at fragment))
        )
        false
    )
)

;; Get platform statistics
(define-read-only (get-platform-stats)
    {
        total-proofs: (var-get total-proofs-generated),
        total-verifications: (var-get total-verifications),
        oracle-count: (var-get oracle-count),
        platform-fee: (var-get platform-fee)
    }
)

;; Check if attribute type is enabled
(define-read-only (is-attribute-enabled (attribute-name (string-ascii 50)))
    (match (map-get? attribute-types { attribute-name: attribute-name })
        attr-type (get enabled attr-type)
        false
    )
)

;; Public functions

;; Initialize user identity
(define-public (initialize-identity)
    (let
        (
            (user tx-sender)
            (existing-identity (get-user-identity user))
        )
        (if (is-some existing-identity)
            ERR-ALREADY-EXISTS
            (begin
                (map-set user-identities
                    { user: user }
                    {
                        total-fragments: u0,
                        reputation-score: u0,
                        endorsement-count: u0,
                        created-at: stacks-block-height,
                        last-activity: stacks-block-height
                    }
                )
                (ok true)
            )
        )
    )
)

;; Create identity fragment (time-locked proof)
(define-public (create-identity-fragment
    (attribute-type (string-ascii 50))
    (proof-hash (buff 32))
    (validity-blocks uint)
)
    (let
        (
            (fragment-id (+ (var-get fragment-counter) u1))
            (user-identity (unwrap! (get-user-identity tx-sender) ERR-IDENTITY-NOT-FOUND))
            (expires-at (+ stacks-block-height validity-blocks))
        )
        ;; Check if attribute type is enabled
        (asserts! (is-attribute-enabled attribute-type) ERR-INVALID-ATTRIBUTE)

        ;; Create the fragment
        (map-set identity-fragments
            { fragment-id: fragment-id }
            {
                owner: tx-sender,
                attribute-type: attribute-type,
                proof-hash: proof-hash,
                created-at: stacks-block-height,
                expires-at: expires-at,
                revoked: false,
                verification-count: u0,
                reputation-score: u0
            }
        )

        ;; Update user identity
        (map-set user-identities
            { user: tx-sender }
            (merge user-identity {
                total-fragments: (+ (get total-fragments user-identity) u1),
                last-activity: stacks-block-height
            })
        )

        ;; Update counters
        (var-set fragment-counter fragment-id)
        (var-set total-proofs-generated (+ (var-get total-proofs-generated) u1))

        (ok fragment-id)
    )
)

;; Verify identity fragment
(define-public (verify-fragment
    (fragment-id uint)
    (attribute-confirmed bool)
    (verification-score uint)
)
    (let
        (
            (fragment (unwrap! (get-identity-fragment fragment-id) ERR-IDENTITY-NOT-FOUND))
            (proof-id (+ (var-get proof-counter) u1))
            (owner-identity (unwrap! (get-user-identity (get owner fragment)) ERR-IDENTITY-NOT-FOUND))
        )
        ;; Check if fragment is valid
        (asserts! (is-fragment-valid fragment-id) ERR-PROOF-EXPIRED)

        ;; Record verification
        (map-set proof-verifications
            { proof-id: proof-id }
            {
                fragment-id: fragment-id,
                verifier: tx-sender,
                verified-at: stacks-block-height,
                attribute-confirmed: attribute-confirmed,
                verification-score: verification-score
            }
        )

        ;; Update fragment verification count and reputation
        (map-set identity-fragments
            { fragment-id: fragment-id }
            (merge fragment {
                verification-count: (+ (get verification-count fragment) u1),
                reputation-score: (+ (get reputation-score fragment) verification-score)
            })
        )

        ;; Update owner reputation if verification is positive
        (if attribute-confirmed
            (map-set user-identities
                { user: (get owner fragment) }
                (merge owner-identity {
                    reputation-score: (+ (get reputation-score owner-identity) verification-score),
                    last-activity: stacks-block-height
                })
            )
            true
        )

        ;; Update counters
        (var-set proof-counter proof-id)
        (var-set total-verifications (+ (var-get total-verifications) u1))

        (ok proof-id)
    )
)

;; Revoke identity fragment
(define-public (revoke-fragment (fragment-id uint))
    (let
        (
            (fragment (unwrap! (get-identity-fragment fragment-id) ERR-IDENTITY-NOT-FOUND))
        )
        ;; Only owner can revoke
        (asserts! (is-eq tx-sender (get owner fragment)) ERR-NOT-AUTHORIZED)

        ;; Mark as revoked
        (map-set identity-fragments
            { fragment-id: fragment-id }
            (merge fragment { revoked: true })
        )

        (ok true)
    )
)

;; Create anonymous endorsement
(define-public (create-endorsement
    (endorsed-user principal)
    (attribute-type (string-ascii 50))
    (endorser-hash (buff 32))
    (weight uint)
)
    (let
        (
            (endorsement-id (+ (var-get endorsement-counter) u1))
            (endorser-identity (unwrap! (get-user-identity tx-sender) ERR-IDENTITY-NOT-FOUND))
            (endorsed-identity (unwrap! (get-user-identity endorsed-user) ERR-IDENTITY-NOT-FOUND))
        )
        ;; Check endorser reputation
        (asserts! (>= (get reputation-score endorser-identity) MIN-REPUTATION-SCORE) ERR-REPUTATION-TOO-LOW)

        ;; Create endorsement
        (map-set endorsements
            { endorsement-id: endorsement-id }
            {
                endorser-hash: endorser-hash,
                endorsed-user: endorsed-user,
                attribute-type: attribute-type,
                weight: weight,
                timestamp: stacks-block-height
            }
        )

        ;; Update endorsed user's endorsement count
        (map-set user-identities
            { user: endorsed-user }
            (merge endorsed-identity {
                endorsement-count: (+ (get endorsement-count endorsed-identity) u1),
                reputation-score: (+ (get reputation-score endorsed-identity) weight)
            })
        )

        ;; Update counter
        (var-set endorsement-counter endorsement-id)

        (ok endorsement-id)
    )
)

;; Register oracle
(define-public (register-oracle (oracle-address principal))
    (let
        (
            (oracle-id (+ (var-get oracle-count) u1))
        )
        ;; Only contract owner can register oracles
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)

        (map-set oracle-registry
            { oracle-id: oracle-id }
            {
                oracle-address: oracle-address,
                reputation: u100,
                total-validations: u0,
                active: true,
                registered-at: stacks-block-height
            }
        )

        (var-set oracle-count oracle-id)

        (ok oracle-id)
    )
)

;; Deactivate oracle
(define-public (deactivate-oracle (oracle-id uint))
    (let
        (
            (oracle (unwrap! (get-oracle-info oracle-id) ERR-ORACLE-NOT-FOUND))
        )
        ;; Only contract owner can deactivate oracles
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)

        (map-set oracle-registry
            { oracle-id: oracle-id }
            (merge oracle { active: false })
        )

        (ok true)
    )
)

;; Register attribute type
(define-public (register-attribute-type
    (attribute-name (string-ascii 50))
    (min-reputation uint)
    (verification-required bool)
)
    (begin
        ;; Only contract owner can register attribute types
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)

        (map-set attribute-types
            { attribute-name: attribute-name }
            {
                enabled: true,
                min-reputation: min-reputation,
                verification-required: verification-required
            }
        )

        (ok true)
    )
)

;; Disable attribute type
(define-public (disable-attribute-type (attribute-name (string-ascii 50)))
    (let
        (
            (attr-type (unwrap! (map-get? attribute-types { attribute-name: attribute-name }) ERR-INVALID-ATTRIBUTE))
        )
        ;; Only contract owner can disable attribute types
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)

        (map-set attribute-types
            { attribute-name: attribute-name }
            (merge attr-type { enabled: false })
        )

        (ok true)
    )
)

;; Update platform fee
(define-public (update-platform-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
        (var-set platform-fee new-fee)
        (ok true)
    )
)

;; Oracle validation function
(define-public (oracle-validate-fragment
    (oracle-id uint)
    (fragment-id uint)
    (validation-score uint)
)
    (let
        (
            (oracle (unwrap! (get-oracle-info oracle-id) ERR-ORACLE-NOT-FOUND))
            (fragment (unwrap! (get-identity-fragment fragment-id) ERR-IDENTITY-NOT-FOUND))
        )
        ;; Check oracle is active
        (asserts! (get active oracle) ERR-NOT-AUTHORIZED)

        ;; Check caller is the registered oracle address
        (asserts! (is-eq tx-sender (get oracle-address oracle)) ERR-NOT-AUTHORIZED)

        ;; Update oracle stats
        (map-set oracle-registry
            { oracle-id: oracle-id }
            (merge oracle {
                total-validations: (+ (get total-validations oracle) u1)
            })
        )

        ;; Update fragment reputation
        (map-set identity-fragments
            { fragment-id: fragment-id }
            (merge fragment {
                reputation-score: (+ (get reputation-score fragment) validation-score)
            })
        )

        (ok true)
    )
)
