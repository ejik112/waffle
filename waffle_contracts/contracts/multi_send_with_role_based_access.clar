;; Multi-Send Contract with Role-Based Access Control
;; Implements granular permissions for senders, admins, and auditors

;; Constants
(define-constant CONTRACT-OWNER tx-sender)
(define-constant ERR-UNAUTHORIZED (err u401))
(define-constant ERR-INVALID-ROLE (err u402))
(define-constant ERR-ALREADY-HAS-ROLE (err u403))
(define-constant ERR-INSUFFICIENT-BALANCE (err u404))
(define-constant ERR-INVALID-AMOUNT (err u405))
(define-constant ERR-INVALID-RECIPIENT (err u406))
(define-constant ERR-TRANSFER-FAILED (err u407))
(define-constant ERR-INVALID-BATCH-SIZE (err u408))
(define-constant ERR-CONTRACT-PAUSED (err u409))
(define-constant ERR-ALREADY-PROCESSED (err u410))

;; Data Variables
(define-data-var contract-paused bool false)
(define-data-var total-sent uint u0)
(define-data-var batch-counter uint u0)
(define-data-var max-batch-size uint u100)

;; Data Maps
;; Role management
(define-map roles 
    { user: principal, role: (string-ascii 20) } 
    bool
)

;; Track send operations for auditing
(define-map send-history
    { batch-id: uint }
    {
        sender: principal,
        total-amount: uint,
        recipient-count: uint,
        timestamp: uint,
        processed: bool
    }
)

;; Track sender statistics
(define-map sender-stats
    { sender: principal }
    {
        total-batches: uint,
        total-amount-sent: uint,
        last-batch-id: uint
    }
)

;; Track individual transfers within batches
(define-map transfer-details
    { batch-id: uint, index: uint }
    {
        recipient: principal,
        amount: uint,
        status: (string-ascii 10)
    }
)

;; Role assignment history for auditing
(define-map role-changes
    { tx-id: uint }
    {
        admin: principal,
        user: principal,
        role: (string-ascii 20),
        action: (string-ascii 10),
        timestamp: uint
    }
)

(define-data-var role-change-counter uint u0)

;; Role checking functions
(define-private (has-role (user principal) (role (string-ascii 20)))
    (default-to false (map-get? roles { user: user, role: role }))
)

(define-read-only (is-admin (user principal))
    (or (is-eq user CONTRACT-OWNER) (has-role user "admin"))
)

(define-read-only (is-sender (user principal))
    (or (is-admin user) (has-role user "sender"))
)

(define-read-only (is-auditor (user principal))
    (or (is-admin user) (has-role user "auditor"))
)

;; Role management functions
(define-public (grant-role (user principal) (role (string-ascii 20)))
    (begin
        (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)
        (asserts! (or (is-eq role "admin") (is-eq role "sender") (is-eq role "auditor")) ERR-INVALID-ROLE)
        (asserts! (not (has-role user role)) ERR-ALREADY-HAS-ROLE)
        
        ;; Grant the role
        (map-set roles { user: user, role: role } true)
        
        ;; Record role change for audit
        (var-set role-change-counter (+ (var-get role-change-counter) u1))
        (map-set role-changes 
            { tx-id: (var-get role-change-counter) }
            {
                admin: tx-sender,
                user: user,
                role: role,
                action: "grant",
                timestamp: block-height
            }
        )
        (ok true)
    )
)

(define-public (revoke-role (user principal) (role (string-ascii 20)))
    (begin
        (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)
        (asserts! (or (is-eq role "admin") (is-eq role "sender") (is-eq role "auditor")) ERR-INVALID-ROLE)
        (asserts! (has-role user role) ERR-UNAUTHORIZED)
        
        ;; Revoke the role
        (map-delete roles { user: user, role: role })
        
        ;; Record role change for audit
        (var-set role-change-counter (+ (var-get role-change-counter) u1))
        (map-set role-changes 
            { tx-id: (var-get role-change-counter) }
            {
                admin: tx-sender,
                user: user,
                role: role,
                action: "revoke",
                timestamp: block-height
            }
        )
        (ok true)
    )
)

;; Contract management functions
(define-public (pause-contract)
    (begin
        (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)
        (var-set contract-paused true)
        (ok true)
    )
)

(define-public (unpause-contract)
    (begin
        (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)
        (var-set contract-paused false)
        (ok true)
    )
)

(define-public (set-max-batch-size (new-size uint))
    (begin
        (asserts! (is-admin tx-sender) ERR-UNAUTHORIZED)
        (asserts! (> new-size u0) ERR-INVALID-AMOUNT)
        (var-set max-batch-size new-size)
        (ok true)
    )
)

;; Main multi-send function
(define-public (multi-send-stx (recipients (list 100 { to: principal, amount: uint })))
    (let
        (
            (batch-id (+ (var-get batch-counter) u1))
            (recipient-count (len recipients))
            (total-amount (fold + (map get-amount recipients) u0))
        )
        ;; Access control and validation
        (asserts! (is-sender tx-sender) ERR-UNAUTHORIZED)
        (asserts! (not (var-get contract-paused)) ERR-CONTRACT-PAUSED)
        (asserts! (> recipient-count u0) ERR-INVALID-BATCH-SIZE)
        (asserts! (<= recipient-count (var-get max-batch-size)) ERR-INVALID-BATCH-SIZE)
        (asserts! (>= (stx-get-balance tx-sender) total-amount) ERR-INSUFFICIENT-BALANCE)
        
        ;; Record batch in history
        (map-set send-history
            { batch-id: batch-id }
            {
                sender: tx-sender,
                total-amount: total-amount,
                recipient-count: recipient-count,
                timestamp: block-height,
                processed: false
            }
        )
        
        ;; Process transfers
        (let
            (
                (send-result (fold process-transfer recipients { batch-id: batch-id, index: u0, success: true }))
            )
            (if (get success send-result)
                (begin
                    ;; Update batch as processed
                    (map-set send-history
                        { batch-id: batch-id }
                        {
                            sender: tx-sender,
                            total-amount: total-amount,
                            recipient-count: recipient-count,
                            timestamp: block-height,
                            processed: true
                        }
                    )
                    ;; Update counters
                    (var-set batch-counter batch-id)
                    (var-set total-sent (+ (var-get total-sent) total-amount))
                    
                    ;; Update sender statistics
                    (let
                        (
                            (current-stats (default-to 
                                { total-batches: u0, total-amount-sent: u0, last-batch-id: u0 }
                                (map-get? sender-stats { sender: tx-sender })
                            ))
                        )
                        (map-set sender-stats
                            { sender: tx-sender }
                            {
                                total-batches: (+ (get total-batches current-stats) u1),
                                total-amount-sent: (+ (get total-amount-sent current-stats) total-amount),
                                last-batch-id: batch-id
                            }
                        )
                    )
                    (ok batch-id)
                )
                ERR-TRANSFER-FAILED
            )
        )
    )
)

;; Helper function to get amount from recipient record
(define-private (get-amount (recipient { to: principal, amount: uint }))
    (get amount recipient)
)

;; Process individual transfer
(define-private (process-transfer 
    (recipient { to: principal, amount: uint }) 
    (context { batch-id: uint, index: uint, success: bool })
)
    (if (get success context)
        (let
            (
                (transfer-result (stx-transfer? (get amount recipient) tx-sender (get to recipient)))
            )
            (map-set transfer-details
                { batch-id: (get batch-id context), index: (get index context) }
                {
                    recipient: (get to recipient),
                    amount: (get amount recipient),
                    status: (if (is-ok transfer-result) "success" "failed")
                }
            )
            {
                batch-id: (get batch-id context),
                index: (+ (get index context) u1),
                success: (is-ok transfer-result)
            }
        )
        context
    )
)

;; Audit functions (read-only)
(define-read-only (get-batch-info (batch-id uint))
    (map-get? send-history { batch-id: batch-id })
)

(define-read-only (get-transfer-detail (batch-id uint) (index uint))
    (map-get? transfer-details { batch-id: batch-id, index: index })
)

(define-read-only (get-role-change (tx-id uint))
    (map-get? role-changes { tx-id: tx-id })
)

(define-read-only (get-contract-stats)
    {
        total-sent: (var-get total-sent),
        total-batches: (var-get batch-counter),
        is-paused: (var-get contract-paused),
        max-batch-size: (var-get max-batch-size)
    }
)

(define-read-only (get-user-roles (user principal))
    {
        is-admin: (is-admin user),
        is-sender: (is-sender user),
        is-auditor: (is-auditor user),
        has-admin-role: (has-role user "admin"),
        has-sender-role: (has-role user "sender"),
        has-auditor-role: (has-role user "auditor")
    }
)

;; Auditor-specific query functions
(define-read-only (get-batch-details (batch-id uint))
    (begin
        (asserts! (is-auditor tx-sender) ERR-UNAUTHORIZED)
        (ok {
            batch-info: (get-batch-info batch-id),
            ;; Return first few transfers as a sample
            transfer-0: (get-transfer-detail batch-id u0),
            transfer-1: (get-transfer-detail batch-id u1),
            transfer-2: (get-transfer-detail batch-id u2)
        })
    )
)

(define-read-only (get-batch-transfers-range (batch-id uint) (start-index uint) (end-index uint))
    (begin
        (asserts! (is-auditor tx-sender) ERR-UNAUTHORIZED)
        (asserts! (<= end-index (+ start-index u10)) ERR-INVALID-BATCH-SIZE) ;; Limit range to 10
        (ok {
            batch-id: batch-id,
            start: start-index,
            end: end-index,
            ;; In practice, you'd implement a more sophisticated range query
            ;; For now, returning specific indexes as example
            transfers: (list
                (get-transfer-detail batch-id start-index)
                (get-transfer-detail batch-id (+ start-index u1))
                (get-transfer-detail batch-id (+ start-index u2))
            )
        })
    )
)

(define-read-only (check-sender-batch (batch-id uint) (sender principal))
    (begin
        (asserts! (is-auditor tx-sender) ERR-UNAUTHORIZED)
        (match (get-batch-info batch-id)
            batch-info (ok (is-eq (get sender batch-info) sender))
            (ok false)
        )
    )
)

(define-read-only (get-sender-stats (sender principal))
    (begin
        (asserts! (is-auditor tx-sender) ERR-UNAUTHORIZED)
        (ok (default-to 
            { total-batches: u0, total-amount-sent: u0, last-batch-id: u0 }
            (map-get? sender-stats { sender: sender })
        ))
    )
)

;; Initialize contract owner as admin
(map-set roles { user: CONTRACT-OWNER, role: "admin" } true)