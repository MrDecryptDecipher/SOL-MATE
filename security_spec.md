# SOL-MATE Security Specification (`security_spec.md`)

## 1. Access Control Model & Roles
- **Unauthenticated Visitors**: Cannot read or write any Firestore collection. Must authenticate via Firebase Auth (Google Sign-In) on the SOL-MATE Public Homepage first.
- **Authenticated Analyst (`request.auth != null`)**:
  - Can read/write their own `/users/{userId}` document and `/users/{userId}/private/{docId}` PII document (storing `name`, `email`, `ipAddress`, `ipDetails`, and `connectedAtIST`).
  - Can create and read their own `/user_activities/{activityId}` records (`resource.data.uid == request.auth.uid`).
  - Can read and train (create/update) shared institutional Persistent Solana Knowledge Graph collections (`/kg_nodes/{nodeId}`, `/kg_edges/{edgeId}`, `/kg_transactions/{txId}`) with validated schema and IST timestamps.
- **Bootstrapped Admin (`sandeep.savethem2@gmail.com`)**:
  - Full read access across audit logs and Knowledge Graph records for platform governance.

## 2. PII & Privacy Isolation
- User `email`, `ipAddress`, `ipDetails`, and `userAgent` are isolated inside `/users/{userId}/private/{docId}` so only the owning user (`request.auth.uid == userId`) or verified admin can read or write them.

## 3. Data Integrity & Immutability
- Every record enforces strict field validation, string length bounds, and IST timestamp presence (`connectedAtIST`, `timestampIST`, `trainedAtIST`).
- Ownership fields (`uid`, `trainedByUid`) cannot be forged on creation or hijacked on update.
