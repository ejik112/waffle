;; Advanced Time-Based Voting Smart Contract
;; Comprehensive voting system with multiple features

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-VOTING-NOT-STARTED (err u101))
(define-constant ERR-VOTING-ENDED (err u102))
(define-constant ERR-ALREADY-VOTED (err u103))
(define-constant ERR-INVALID-VOTE (err u104))
(define-constant ERR-VOTING-PERIOD-INVALID (err u105))
(define-constant ERR-NOT-ELIGIBLE (err u106))
(define-constant ERR-INSUFFICIENT-TOKENS (err u107))
(define-constant ERR-PROPOSAL-NOT-FOUND (err u108))
(define-constant ERR-QUORUM-NOT-MET (err u109))
(define-constant ERR-INVALID-PROPOSAL (err u110))
(define-constant ERR-DELEGATION-FAILED (err u111))
(define-constant ERR-INVALID-WEIGHT (err u112))

;; Contract owner and admin roles
(define-constant CONTRACT-OWNER tx-sender)
(define-map admins principal bool)

;; Voting configuration
(define-data-var current-proposal-id uint u0)
(define-data-var min-token-balance uint u1000) ;; Minimum tokens required to vote
(define-data-var quorum-percentage uint u30) ;; 30% quorum required
(define-data-var voting-fee uint u10) ;; Fee in microSTX to cast vote

;; Vote options
(define-constant VOTE-YES u1)
(define-constant VOTE-NO u2)
(define-constant VOTE-ABSTAIN u3)

;; Proposal structure
(define-map proposals uint {
  title: (string-ascii 100),
  description: (string-ascii 500),
  proposer: principal,
  start-height: uint,
  end-height: uint,
  active: bool,
  executed: bool,
  votes-yes: uint,
  votes-no: uint,
  votes-abstain: uint,
  total-votes: uint,
  quorum-met: bool,
  creation-time: uint,
  category: (string-ascii 50)
})

;; Voting records with weights
(define-map votes { proposal-id: uint, voter: principal } {
  vote: uint,
  weight: uint,
  timestamp: uint,
  delegated-from: (optional principal)
})

;; Eligible voters whitelist
(define-map eligible-voters principal bool)

;; Vote delegation
(define-map delegations principal principal) ;; delegator -> delegate

;; Voter profiles with reputation
(define-map voter-profiles principal {
  total-votes-cast: uint,
  reputation-score: uint,
  tokens-staked: uint,
  last-vote-time: uint,
  delegate: (optional principal)
})

;; Voting history for analytics
(define-map voting-history uint {
  proposal-id: uint,
  voter: principal,
  vote: uint,
  block-height: uint,
  weight: uint
})

(define-data-var history-counter uint u0)

;; Token-weighted voting
(define-map token-weights principal uint)

;; Multi-choice proposals (beyond yes/no/abstain)
(define-map proposal-options { proposal-id: uint, option-id: uint } {
  description: (string-ascii 200),
  votes: uint
})

;; Read-only functions

;; Get proposal details
(define-read-only (get-proposal (proposal-id uint))
  (map-get? proposals proposal-id)
)

;; Get current proposal ID
(define-read-only (get-current-proposal-id)
  (var-get current-proposal-id)
)

;; Check if user is eligible to vote
(define-read-only (is-eligible-voter (user principal))
  (default-to false (map-get? eligible-voters user))
)

;; Get user's vote for a proposal
(define-read-only (get-user-vote (proposal-id uint) (user principal))
  (map-get? votes { proposal-id: proposal-id, voter: user })
)

;; Check if user has voted on proposal
(define-read-only (has-voted (proposal-id uint) (user principal))
  (is-some (map-get? votes { proposal-id: proposal-id, voter: user }))
)

;; Get proposal results
(define-read-only (get-proposal-results (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (some {
      proposal-id: proposal-id,
      votes-yes: (get votes-yes proposal),
      votes-no: (get votes-no proposal),
      votes-abstain: (get votes-abstain proposal),
      total-votes: (get total-votes proposal),
      quorum-met: (get quorum-met proposal),
      active: (get active proposal),
      executed: (get executed proposal)
    })
    none
  )
)

;; Check if proposal is currently active
(define-read-only (is-proposal-active (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (and 
      (get active proposal)
      (>= block-height (get start-height proposal))
      (<= block-height (get end-height proposal))
    )
    false
  )
)

;; Get voter profile
(define-read-only (get-voter-profile (user principal))
  (map-get? voter-profiles user)
)

;; Get delegation info
(define-read-only (get-delegation (delegator principal))
  (map-get? delegations delegator)
)

;; Calculate voting weight based on tokens
(define-read-only (calculate-voting-weight (user principal))
  (let ((token-balance (default-to u0 (map-get? token-weights user))))
    (if (>= token-balance (var-get min-token-balance))
      (+ u1 (/ token-balance u1000)) ;; Base weight 1 + bonus based on tokens
      u0
    )
  )
)

;; Check if quorum is met for proposal
(define-read-only (check-quorum (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (let ((total-eligible (get-total-eligible-voters))
                   (total-votes (get total-votes proposal))
                   (required-quorum (/ (* total-eligible (var-get quorum-percentage)) u100)))
               (>= total-votes required-quorum))
    false
  )
)

;; Get total eligible voters (helper function)
(define-read-only (get-total-eligible-voters)
  ;; This would need to be tracked separately in a real implementation
  u100 ;; Placeholder
)

;; Get voting statistics
(define-read-only (get-voting-statistics (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (some {
      participation-rate: (if (> (get-total-eligible-voters) u0)
                           (/ (* (get total-votes proposal) u100) (get-total-eligible-voters))
                           u0),
      yes-percentage: (if (> (get total-votes proposal) u0)
                       (/ (* (get votes-yes proposal) u100) (get total-votes proposal))
                       u0),
      no-percentage: (if (> (get total-votes proposal) u0)
                      (/ (* (get votes-no proposal) u100) (get total-votes proposal))
                      u0),
      abstain-percentage: (if (> (get total-votes proposal) u0)
                          (/ (* (get votes-abstain proposal) u100) (get total-votes proposal))
                          u0)
    })
    none
  )
)

;; Private functions

;; Validate vote option
(define-private (is-valid-vote (vote uint))
  (or (is-eq vote VOTE-YES) (is-eq vote VOTE-NO) (is-eq vote VOTE-ABSTAIN))
)

;; Update proposal vote counts
(define-private (update-proposal-votes (proposal-id uint) (vote uint) (weight uint))
  (match (map-get? proposals proposal-id)
    proposal (let ((updated-proposal 
                    (if (is-eq vote VOTE-YES)
                      (merge proposal { 
                        votes-yes: (+ (get votes-yes proposal) weight),
                        total-votes: (+ (get total-votes proposal) weight)
                      })
                      (if (is-eq vote VOTE-NO)
                        (merge proposal { 
                          votes-no: (+ (get votes-no proposal) weight),
                          total-votes: (+ (get total-votes proposal) weight)
                        })
                        (merge proposal { 
                          votes-abstain: (+ (get votes-abstain proposal) weight),
                          total-votes: (+ (get total-votes proposal) weight)
                        })
                      )
                    )))
              (map-set proposals proposal-id updated-proposal)
              true)
    false
  )
)

;; Update voter profile
(define-private (update-voter-profile (user principal))
  (let ((current-profile (default-to 
                          { total-votes-cast: u0, reputation-score: u0, tokens-staked: u0, 
                            last-vote-time: u0, delegate: none }
                          (map-get? voter-profiles user))))
    (map-set voter-profiles user (merge current-profile {
      total-votes-cast: (+ (get total-votes-cast current-profile) u1),
      reputation-score: (+ (get reputation-score current-profile) u1),
      last-vote-time: block-height
    }))
  )
)

;; Record voting history
(define-private (record-vote-history (proposal-id uint) (voter principal) (vote uint) (weight uint))
  (let ((history-id (var-get history-counter)))
    (map-set voting-history history-id {
      proposal-id: proposal-id,
      voter: voter,
      vote: vote,
      block-height: block-height,
      weight: weight
    })
    (var-set history-counter (+ history-id u1))
  )
)

;; Public functions

;; Add admin
(define-public (add-admin (admin principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-set admins admin true)
    (ok true)
  )
)

;; Remove admin
(define-public (remove-admin (admin principal))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (map-delete admins admin)
    (ok true)
  )
)

;; Add eligible voter
(define-public (add-eligible-voter (voter principal))
  (begin
    (asserts! (or (is-eq tx-sender CONTRACT-OWNER) 
                  (default-to false (map-get? admins tx-sender))) ERR-NOT-AUTHORIZED)
    (map-set eligible-voters voter true)
    (ok true)
  )
)

;; Remove eligible voter
(define-public (remove-eligible-voter (voter principal))
  (begin
    (asserts! (or (is-eq tx-sender CONTRACT-OWNER) 
                  (default-to false (map-get? admins tx-sender))) ERR-NOT-AUTHORIZED)
    (map-delete eligible-voters voter)
    (ok true)
  )
)

;; Set token weight for voter
(define-public (set-token-weight (user principal) (weight uint))
  (begin
    (asserts! (or (is-eq tx-sender CONTRACT-OWNER) 
                  (default-to false (map-get? admins tx-sender))) ERR-NOT-AUTHORIZED)
    (asserts! (> weight u0) ERR-INVALID-WEIGHT)
    (map-set token-weights user weight)
    (ok true)
  )
)

;; Create new proposal
(define-public (create-proposal 
                (title (string-ascii 100))
                (description (string-ascii 500))
                (start-height uint)
                (end-height uint)
                (category (string-ascii 50)))
  (let ((proposal-id (+ (var-get current-proposal-id) u1)))
    (begin
      ;; Validate proposal parameters
      (asserts! (> end-height start-height) ERR-VOTING-PERIOD-INVALID)
      (asserts! (> start-height block-height) ERR-VOTING-PERIOD-INVALID)
      (asserts! (is-eligible-voter tx-sender) ERR-NOT-ELIGIBLE)
      
      ;; Create proposal
      (map-set proposals proposal-id {
        title: title,
        description: description,
        proposer: tx-sender,
        start-height: start-height,
        end-height: end-height,
        active: true,
        executed: false,
        votes-yes: u0,
        votes-no: u0,
        votes-abstain: u0,
        total-votes: u0,
        quorum-met: false,
        creation-time: block-height,
        category: category
      })
      
      ;; Update current proposal ID
      (var-set current-proposal-id proposal-id)
      
      (ok proposal-id)
    )
  )
)

;; Cast vote with delegation support
(define-public (cast-vote (proposal-id uint) (vote uint))
  (let ((voter-weight (calculate-voting-weight tx-sender))
        (delegated-from (map-get? delegations tx-sender)))
    (begin
      ;; Validate vote
      (asserts! (is-valid-vote vote) ERR-INVALID-VOTE)
      (asserts! (is-proposal-active proposal-id) ERR-VOTING-NOT-STARTED)
      (asserts! (is-eligible-voter tx-sender) ERR-NOT-ELIGIBLE)
      (asserts! (> voter-weight u0) ERR-INSUFFICIENT-TOKENS)
      (asserts! (not (has-voted proposal-id tx-sender)) ERR-ALREADY-VOTED)
      
      ;; Pay voting fee
      (try! (stx-transfer? (var-get voting-fee) tx-sender CONTRACT-OWNER))
      
      ;; Record vote
      (map-set votes { proposal-id: proposal-id, voter: tx-sender } {
        vote: vote,
        weight: voter-weight,
        timestamp: block-height,
        delegated-from: delegated-from
      })
      
      ;; Update proposal counts
      (update-proposal-votes proposal-id vote voter-weight)
      
      ;; Update voter profile
      (update-voter-profile tx-sender)
      
      ;; Record in history
      (record-vote-history proposal-id tx-sender vote voter-weight)
      
      ;; Check and update quorum
      (let ((proposal (unwrap! (map-get? proposals proposal-id) ERR-PROPOSAL-NOT-FOUND)))
        (if (check-quorum proposal-id)
          (map-set proposals proposal-id (merge proposal { quorum-met: true }))
          true
        )
      )
      
      (ok true)
    )
  )
)

;; Delegate vote
(define-public (delegate-vote (delegate principal))
  (begin
    (asserts! (is-eligible-voter tx-sender) ERR-NOT-ELIGIBLE)
    (asserts! (is-eligible-voter delegate) ERR-NOT-ELIGIBLE)
    (asserts! (not (is-eq tx-sender delegate)) ERR-DELEGATION-FAILED)
    
    (map-set delegations tx-sender delegate)
    
    ;; Update voter profile
    (let ((current-profile (default-to 
                            { total-votes-cast: u0, reputation-score: u0, tokens-staked: u0, 
                              last-vote-time: u0, delegate: none }
                            (map-get? voter-profiles tx-sender))))
      (map-set voter-profiles tx-sender (merge current-profile { delegate: (some delegate) }))
    )
    
    (ok true)
  )
)

;; Remove delegation
(define-public (remove-delegation)
  (begin
    (asserts! (is-eligible-voter tx-sender) ERR-NOT-ELIGIBLE)
    
    (map-delete delegations tx-sender)
    
    ;; Update voter profile
    (let ((current-profile (default-to 
                            { total-votes-cast: u0, reputation-score: u0, tokens-staked: u0, 
                              last-vote-time: u0, delegate: none }
                            (map-get? voter-profiles tx-sender))))
      (map-set voter-profiles tx-sender (merge current-profile { delegate: none }))
    )
    
    (ok true)
  )
)

;; End proposal (admin only)
(define-public (end-proposal (proposal-id uint))
  (begin
    (asserts! (or (is-eq tx-sender CONTRACT-OWNER) 
                  (default-to false (map-get? admins tx-sender))) ERR-NOT-AUTHORIZED)
    
    (match (map-get? proposals proposal-id)
      proposal (begin
                 (map-set proposals proposal-id (merge proposal { active: false }))
                 (ok true))
      ERR-PROPOSAL-NOT-FOUND
    )
  )
)

;; Execute proposal (if passed and quorum met)
(define-public (execute-proposal (proposal-id uint))
  (match (map-get? proposals proposal-id)
    proposal (begin
               (asserts! (not (get active proposal)) ERR-VOTING-NOT-STARTED)
               (asserts! (not (get executed proposal)) ERR-INVALID-PROPOSAL)
               (asserts! (get quorum-met proposal) ERR-QUORUM-NOT-MET)
               (asserts! (> (get votes-yes proposal) (get votes-no proposal)) ERR-INVALID-PROPOSAL)
               
               (map-set proposals proposal-id (merge proposal { executed: true }))
               (ok true))
    ERR-PROPOSAL-NOT-FOUND
  )
)

;; Update voting parameters (admin only)
(define-public (update-voting-parameters (min-tokens uint) (quorum uint) (fee uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    (asserts! (<= quorum u100) ERR-INVALID-PROPOSAL) ;; Max 100% quorum
    
    (var-set min-token-balance min-tokens)
    (var-set quorum-percentage quorum)
    (var-set voting-fee fee)
    
    (ok true)
  )
)

;; Emergency stop (owner only)
(define-public (emergency-stop (proposal-id uint))
  (begin
    (asserts! (is-eq tx-sender CONTRACT-OWNER) ERR-NOT-AUTHORIZED)
    
    (match (map-get? proposals proposal-id)
      proposal (begin
                 (map-set proposals proposal-id (merge proposal { active: false }))
                 (ok true))
      ERR-PROPOSAL-NOT-FOUND
    )
  )
)