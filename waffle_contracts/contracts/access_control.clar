;; Enhanced File Access Control Smart Contract
;; Comprehensive file management with advanced permissions and features

;; Error codes
(define-constant ERR-NOT-FOUND (err u404))
(define-constant ERR-UNAUTHORIZED (err u401))
(define-constant ERR-ALREADY-EXISTS (err u409))
(define-constant ERR-INVALID-PERMISSION (err u400))
(define-constant ERR-INVALID-INPUT (err u402))
(define-constant ERR-QUOTA-EXCEEDED (err u413))
(define-constant ERR-FILE-LOCKED (err u423))
(define-constant ERR-EXPIRED (err u410))
(define-constant ERR-ADMIN-ONLY (err u403))

;; Permission types
(define-constant PERMISSION-READ u1)
(define-constant PERMISSION-WRITE u2)
(define-constant PERMISSION-READ-WRITE u3)
(define-constant PERMISSION-ADMIN u4)

;; File status types
(define-constant STATUS-ACTIVE u1)
(define-constant STATUS-LOCKED u2)
(define-constant STATUS-ARCHIVED u3)
(define-constant STATUS-DELETED u4)

;; Constants
(define-constant MAX-FILE-SIZE u1000000) ;; 1MB in bytes
(define-constant MAX-FILES-PER-USER u100)
(define-constant MAX-SHARED-USERS u50)
(define-constant CONTRACT-VERSION u1)

;; Data variables
(define-data-var contract-owner principal tx-sender)
(define-data-var contract-paused bool false)
(define-data-var total-files uint u0)
(define-data-var global-file-counter uint u0)

;; Data structures

;; Enhanced file metadata
(define-map files
  { file-id: (string-ascii 64) }
  {
    owner: principal,
    name: (string-ascii 128),
    description: (string-ascii 256),
    file-type: (string-ascii 32),
    size: uint,
    checksum: (string-ascii 64),
    status: uint,
    created-at: uint,
    updated-at: uint,
    last-accessed: uint,
    access-count: uint,
    is-public: bool,
    expiry-block: (optional uint),
    parent-folder: (optional (string-ascii 64))
  }
)

;; Enhanced file permissions with expiry and conditions
(define-map file-permissions
  { 
    file-id: (string-ascii 64),
    user: principal
  }
  {
    permission: uint,
    granted-at: uint,
    granted-by: principal,
    expires-at: (optional uint),
    access-count: uint,
    max-access-count: (optional uint),
    conditions: (string-ascii 128)
  }
)

;; User file quotas and limits
(define-map user-quotas
  { user: principal }
  {
    files-created: uint,
    total-size-used: uint,
    max-files: uint,
    max-storage: uint,
    is-premium: bool
  }
)

;; File sharing groups
(define-map sharing-groups
  { group-id: (string-ascii 32) }
  {
    name: (string-ascii 64),
    owner: principal,
    created-at: uint,
    member-count: uint,
    is-active: bool
  }
)

;; Group memberships
(define-map group-members
  { 
    group-id: (string-ascii 32),
    user: principal
  }
  {
    joined-at: uint,
    role: uint,
    added-by: principal
  }
)

;; File group permissions
(define-map group-file-permissions
  {
    file-id: (string-ascii 64),
    group-id: (string-ascii 32)
  }
  {
    permission: uint,
    granted-at: uint,
    granted-by: principal
  }
)

;; File versions for version control
(define-map file-versions
  {
    file-id: (string-ascii 64),
    version: uint
  }
  {
    checksum: (string-ascii 64),
    size: uint,
    created-at: uint,
    created-by: principal,
    comment: (string-ascii 256)
  }
)

;; Access logs for auditing
(define-map access-logs
  {
    file-id: (string-ascii 64),
    user: principal,
    timestamp: uint
  }
  {
    action: (string-ascii 32),
    ip-hash: (string-ascii 64),
    success: bool
  }
)

;; File tags for organization
(define-map file-tags
  {
    file-id: (string-ascii 64),
    tag: (string-ascii 32)
  }
  { added-at: uint }
)

;; Backup configurations
(define-map backup-configs
  { file-id: (string-ascii 64) }
  {
    backup-enabled: bool,
    backup-frequency: uint,
    last-backup: uint,
    backup-location: (string-ascii 128)
  }
)

;; Private helper functions

;; Check if contract is paused
(define-private (check-contract-active)
  (not (var-get contract-paused))
)

;; Check if user has specific permission (enhanced with groups and expiry)
(define-private (has-permission-enhanced (file-id (string-ascii 64)) (user principal) (required-permission uint))
  (let (
    (file-info (map-get? files { file-id: file-id }))
    (permission-info (map-get? file-permissions { file-id: file-id, user: user }))
  )
    (match file-info
      file-data
        (if (is-eq (get owner file-data) user)
          true ;; Owner has all permissions
          (if (get is-public file-data)
            (is-eq required-permission PERMISSION-READ) ;; Public files allow read access
            (or
              ;; Check direct permissions
              (match permission-info
                perm-data
                  (and
                    (or 
                      (is-eq (get permission perm-data) PERMISSION-READ-WRITE)
                      (is-eq (get permission perm-data) PERMISSION-ADMIN)
                      (is-eq (get permission perm-data) required-permission)
                    )
                    ;; Check if permission hasn't expired
                    (match (get expires-at perm-data)
                      expiry (< block-height expiry)
                      true
                    )
                    ;; Check access count limits
                    (match (get max-access-count perm-data)
                      max-count (< (get access-count perm-data) max-count)
                      true
                    )
                  )
                false
              )
              ;; Check group permissions
              (check-group-permissions file-id user required-permission)
            )
          )
        )
      false
    )
  )
)

;; Check group permissions for a user
(define-private (check-group-permissions (file-id (string-ascii 64)) (user principal) (required-permission uint))
  ;; Simplified - in a full implementation, this would iterate through user's groups
  false
)

;; Validate permission value
(define-private (is-valid-permission (permission uint))
  (or 
    (is-eq permission PERMISSION-READ)
    (is-eq permission PERMISSION-WRITE)
    (is-eq permission PERMISSION-READ-WRITE)
    (is-eq permission PERMISSION-ADMIN)
  )
)

;; Check user quotas
(define-private (check-user-quota (user principal) (file-size uint))
  (let (
    (quota-info (default-to 
      { files-created: u0, total-size-used: u0, max-files: u10, max-storage: u10000000, is-premium: false }
      (map-get? user-quotas { user: user })
    ))
  )
    (and
      (< (get files-created quota-info) (get max-files quota-info))
      (< (+ (get total-size-used quota-info) file-size) (get max-storage quota-info))
    )
  )
)

;; Update user quota
(define-private (update-user-quota (user principal) (file-size uint))
  (let (
    (current-quota (default-to 
      { files-created: u0, total-size-used: u0, max-files: u10, max-storage: u10000000, is-premium: false }
      (map-get? user-quotas { user: user })
    ))
  )
    (map-set user-quotas
      { user: user }
      (merge current-quota {
        files-created: (+ (get files-created current-quota) u1),
        total-size-used: (+ (get total-size-used current-quota) file-size)
      })
    )
  )
)

;; Log access attempt
(define-private (log-access (file-id (string-ascii 64)) (user principal) (action (string-ascii 32)) (success bool))
  (map-set access-logs
    { file-id: file-id, user: user, timestamp: block-height }
    { action: action, ip-hash: "hash-placeholder", success: success }
  )
)

;; Public functions

;; Enhanced file creation with metadata
(define-public (create-file-enhanced 
  (file-id (string-ascii 64))
  (name (string-ascii 128))
  (description (string-ascii 256))
  (file-type (string-ascii 32))
  (size uint)
  (checksum (string-ascii 64))
  (is-public bool)
  (expiry-blocks (optional uint))
)
  (let (
    (existing-file (map-get? files { file-id: file-id }))
  )
    (if (not (check-contract-active))
      ERR-ADMIN-ONLY
      (if (is-some existing-file)
        ERR-ALREADY-EXISTS
        (if (> size MAX-FILE-SIZE)
          ERR-QUOTA-EXCEEDED
          (if (not (check-user-quota tx-sender size))
            ERR-QUOTA-EXCEEDED
            (begin
              (map-set files
                { file-id: file-id }
                {
                  owner: tx-sender,
                  name: name,
                  description: description,
                  file-type: file-type,
                  size: size,
                  checksum: checksum,
                  status: STATUS-ACTIVE,
                  created-at: block-height,
                  updated-at: block-height,
                  last-accessed: block-height,
                  access-count: u0,
                  is-public: is-public,
                  expiry-block: (match expiry-blocks exp (some (+ block-height exp)) none),
                  parent-folder: none
                }
              )
              (update-user-quota tx-sender size)
              (var-set total-files (+ (var-get total-files) u1))
              (var-set global-file-counter (+ (var-get global-file-counter) u1))
              (print { 
                event: "file-created-enhanced", 
                file-id: file-id, 
                owner: tx-sender,
                name: name,
                size: size,
                is-public: is-public
              })
              (ok true)
            )
          )
        )
      )
    )
  )
)

;; Grant permission with expiry and limits
(define-public (grant-permission-enhanced 
  (file-id (string-ascii 64)) 
  (user principal) 
  (permission uint)
  (expires-in-blocks (optional uint))
  (max-access-count (optional uint))
  (conditions (string-ascii 128))
)
  (let (
    (file-info (map-get? files { file-id: file-id }))
  )
    (if (not (is-valid-permission permission))
      ERR-INVALID-PERMISSION
      (match file-info
        file-data
          (if (is-eq (get owner file-data) tx-sender)
            (begin
              (map-set file-permissions
                { file-id: file-id, user: user }
                {
                  permission: permission,
                  granted-at: block-height,
                  granted-by: tx-sender,
                  expires-at: (match expires-in-blocks exp (some (+ block-height exp)) none),
                  access-count: u0,
                  max-access-count: max-access-count,
                  conditions: conditions
                }
              )
              (print { 
                event: "permission-granted-enhanced", 
                file-id: file-id, 
                user: user, 
                permission: permission,
                expires-at: (match expires-in-blocks exp (some (+ block-height exp)) none),
                granted-by: tx-sender
              })
              (ok true)
            )
            ERR-UNAUTHORIZED
          )
        ERR-NOT-FOUND
      )
    )
  )
)

;; Create sharing group
(define-public (create-sharing-group (group-id (string-ascii 32)) (name (string-ascii 64)))
  (let (
    (existing-group (map-get? sharing-groups { group-id: group-id }))
  )
    (if (is-some existing-group)
      ERR-ALREADY-EXISTS
      (begin
        (map-set sharing-groups
          { group-id: group-id }
          {
            name: name,
            owner: tx-sender,
            created-at: block-height,
            member-count: u1,
            is-active: true
          }
        )
        ;; Add creator as first member
        (map-set group-members
          { group-id: group-id, user: tx-sender }
          { joined-at: block-height, role: u1, added-by: tx-sender }
        )
        (print { event: "group-created", group-id: group-id, name: name, owner: tx-sender })
        (ok true)
      )
    )
  )
)

;; Add user to sharing group
(define-public (add-to-group (group-id (string-ascii 32)) (user principal) (role uint))
  (let (
    (group-info (map-get? sharing-groups { group-id: group-id }))
  )
    (match group-info
      group-data
        (if (is-eq (get owner group-data) tx-sender)
          (begin
            (map-set group-members
              { group-id: group-id, user: user }
              { joined-at: block-height, role: role, added-by: tx-sender }
            )
            (map-set sharing-groups
              { group-id: group-id }
              (merge group-data { member-count: (+ (get member-count group-data) u1) })
            )
            (print { event: "user-added-to-group", group-id: group-id, user: user, role: role })
            (ok true)
          )
          ERR-UNAUTHORIZED
        )
      ERR-NOT-FOUND
    )
  )
)

;; Grant group permission to file
(define-public (grant-group-permission (file-id (string-ascii 64)) (group-id (string-ascii 32)) (permission uint))
  (let (
    (file-info (map-get? files { file-id: file-id }))
    (group-info (map-get? sharing-groups { group-id: group-id }))
  )
    (if (and (is-some file-info) (is-some group-info))
      (if (is-eq (get owner (unwrap-panic file-info)) tx-sender)
        (begin
          (map-set group-file-permissions
            { file-id: file-id, group-id: group-id }
            { permission: permission, granted-at: block-height, granted-by: tx-sender }
          )
          (print { event: "group-permission-granted", file-id: file-id, group-id: group-id, permission: permission })
          (ok true)
        )
        ERR-UNAUTHORIZED
      )
      ERR-NOT-FOUND
    )
  )
)

;; Lock/unlock file
(define-public (set-file-status (file-id (string-ascii 64)) (status uint))
  (let (
    (file-info (map-get? files { file-id: file-id }))
  )
    (match file-info
      file-data
        (if (is-eq (get owner file-data) tx-sender)
          (begin
            (map-set files
              { file-id: file-id }
              (merge file-data { status: status, updated-at: block-height })
            )
            (print { event: "file-status-changed", file-id: file-id, status: status })
            (ok true)
          )
          ERR-UNAUTHORIZED
        )
      ERR-NOT-FOUND
    )
  )
)

;; Create file version
(define-public (create-file-version 
  (file-id (string-ascii 64)) 
  (version uint) 
  (checksum (string-ascii 64))
  (size uint)
  (comment (string-ascii 256))
)
  (let (
    (file-info (map-get? files { file-id: file-id }))
  )
    (match file-info
      file-data
        (if (has-permission-enhanced file-id tx-sender PERMISSION-WRITE)
          (begin
            (map-set file-versions
              { file-id: file-id, version: version }
              {
                checksum: checksum,
                size: size,
                created-at: block-height,
                created-by: tx-sender,
                comment: comment
              }
            )
            (print { event: "version-created", file-id: file-id, version: version, created-by: tx-sender })
            (ok true)
          )
          ERR-UNAUTHORIZED
        )
      ERR-NOT-FOUND
    )
  )
)

;; Add tag to file
(define-public (add-file-tag (file-id (string-ascii 64)) (tag (string-ascii 32)))
  (let (
    (file-info (map-get? files { file-id: file-id }))
  )
    (match file-info
      file-data
        (if (has-permission-enhanced file-id tx-sender PERMISSION-WRITE)
          (begin
            (map-set file-tags
              { file-id: file-id, tag: tag }
              { added-at: block-height }
            )
            (print { event: "tag-added", file-id: file-id, tag: tag })
            (ok true)
          )
          ERR-UNAUTHORIZED
        )
      ERR-NOT-FOUND
    )
  )
)

;; Configure backup settings
(define-public (configure-backup 
  (file-id (string-ascii 64))
  (backup-enabled bool)
  (backup-frequency uint)
  (backup-location (string-ascii 128))
)
  (let (
    (file-info (map-get? files { file-id: file-id }))
  )
    (match file-info
      file-data
        (if (is-eq (get owner file-data) tx-sender)
          (begin
            (map-set backup-configs
              { file-id: file-id }
              {
                backup-enabled: backup-enabled,
                backup-frequency: backup-frequency,
                last-backup: block-height,
                backup-location: backup-location
              }
            )
            (print { event: "backup-configured", file-id: file-id, enabled: backup-enabled })
            (ok true)
          )
          ERR-UNAUTHORIZED
        )
      ERR-NOT-FOUND
    )
  )
)

;; Enhanced access check with logging
(define-public (request-file-access (file-id (string-ascii 64)) (action (string-ascii 32)))
  (let (
    (file-info (map-get? files { file-id: file-id }))
    (required-permission (if (is-eq action "read") PERMISSION-READ PERMISSION-WRITE))
  )
    (match file-info
      file-data
        (let (
          (has-access (has-permission-enhanced file-id tx-sender required-permission))
          (file-active (is-eq (get status file-data) STATUS-ACTIVE))
          (not-expired (match (get expiry-block file-data)
            expiry (< block-height expiry)
            true
          ))
        )
          (begin
            (log-access file-id tx-sender action (and has-access file-active not-expired))
            (if (and has-access file-active not-expired)
              (begin
                ;; Update access statistics
                (map-set files
                  { file-id: file-id }
                  (merge file-data { 
                    last-accessed: block-height,
                    access-count: (+ (get access-count file-data) u1)
                  })
                )
                (ok true)
              )
              (if (not file-active)
                ERR-FILE-LOCKED
                (if (not not-expired)
                  ERR-EXPIRED
                  ERR-UNAUTHORIZED
                )
              )
            )
          )
        )
      ERR-NOT-FOUND
    )
  )
)

;; Admin functions

;; Pause/unpause contract (admin only)
(define-public (set-contract-pause (paused bool))
  (if (is-eq tx-sender (var-get contract-owner))
    (begin
      (var-set contract-paused paused)
      (print { event: "contract-pause-changed", paused: paused })
      (ok true)
    )
    ERR-ADMIN-ONLY
  )
)

;; Update user quota limits (admin only)
(define-public (update-user-quota-limits 
  (user principal) 
  (max-files uint) 
  (max-storage uint) 
  (is-premium bool)
)
  (if (is-eq tx-sender (var-get contract-owner))
    (let (
      (current-quota (default-to 
        { files-created: u0, total-size-used: u0, max-files: u10, max-storage: u10000000, is-premium: false }
        (map-get? user-quotas { user: user })
      ))
    )
      (begin
        (map-set user-quotas
          { user: user }
          (merge current-quota { max-files: max-files, max-storage: max-storage, is-premium: is-premium })
        )
        (print { event: "quota-updated", user: user, max-files: max-files, max-storage: max-storage })
        (ok true)
      )
    )
    ERR-ADMIN-ONLY
  )
)

;; Read-only functions

;; Get enhanced file information
(define-read-only (get-file-info-enhanced (file-id (string-ascii 64)))
  (map-get? files { file-id: file-id })
)

;; Get user's enhanced permission info
(define-read-only (get-user-permission-enhanced (file-id (string-ascii 64)) (user principal))
  (map-get? file-permissions { file-id: file-id, user: user })
)

;; Get user quota information
(define-read-only (get-user-quota (user principal))
  (map-get? user-quotas { user: user })
)

;; Get sharing group info
(define-read-only (get-sharing-group (group-id (string-ascii 32)))
  (map-get? sharing-groups { group-id: group-id })
)

;; Get file version info
(define-read-only (get-file-version (file-id (string-ascii 64)) (version uint))
  (map-get? file-versions { file-id: file-id, version: version })
)

;; Get backup configuration
(define-read-only (get-backup-config (file-id (string-ascii 64)))
  (map-get? backup-configs { file-id: file-id })
)

;; Get access log
(define-read-only (get-access-log (file-id (string-ascii 64)) (user principal) (timestamp uint))
  (map-get? access-logs { file-id: file-id, user: user, timestamp: timestamp })
)

;; Get file tags
(define-read-only (get-file-tag (file-id (string-ascii 64)) (tag (string-ascii 32)))
  (map-get? file-tags { file-id: file-id, tag: tag })
)

;; Get contract statistics
(define-read-only (get-contract-stats)
  {
    total-files: (var-get total-files),
    global-file-counter: (var-get global-file-counter),
    contract-version: CONTRACT-VERSION,
    is-paused: (var-get contract-paused)
  }
)

;; Check if user can perform specific action (comprehensive check)
(define-read-only (can-perform-action (file-id (string-ascii 64)) (user principal) (action (string-ascii 32)))
  (let (
    (file-info (map-get? files { file-id: file-id }))
    (required-permission (if (is-eq action "read") PERMISSION-READ PERMISSION-WRITE))
  )
    (match file-info
      file-data
        (and
          (has-permission-enhanced file-id user required-permission)
          (is-eq (get status file-data) STATUS-ACTIVE)
          (match (get expiry-block file-data)
            expiry (< block-height expiry)
            true
          )
        )
      false
    )
  )
)