# TOTP Replay Prevention: Concurrency and Persistence

## Context

The proposed gopasslib design introduces `last_used_counter` to prevent reuse of previously accepted TOTP counters.

The existing totp package verifies codes against the current time period and configured lookback window. The counter-aware verification refactor identifies the matching counter, but it does not independently provide replay protection.

Reliable replay prevention requires both validating the code and ensuring that its counter is consumed at most once, including under concurrent requests.

## 1. The concurrency problem

Consider two requests submitting the same valid TOTP code, matching counter 101.

1. Request A loads a credential with `last_used_counter` = 100.
2. Request B loads the same credential with `last_used_counter` = 100.
3. Both verify the code and confirm that 101 > 100.
4. Both update their credential copies to counter 101.
5. Both persist their changes and return authentication success.

The same code has now been accepted twice.

Even strongly consistent individual reads and writes do not guarantee that a multi-step read-modify-write operation is atomic.

This can occur within a single application process or across multiple application instances.

## 2. Option A: Application-managed persistence

Under this approach, gopasslib returns the verified counter, and the application handles replay checks and persistence.

Advantages:

* No database abstraction is required in gopasslib.
* Applications retain control over their storage and transaction models.
* The library remains relatively simple.

Trade-offs:

* Every application must correctly implement atomic replay protection.
* A straightforward load-verify-save implementation can permit concurrent reuse.
* Code verification and durable counter advancement can become disconnected.

This approach provides flexibility but places security-critical responsibility on callers.

## 3. Option B: Library-defined atomic persistence contract

Under this approach, gopasslib coordinates verification and replay protection, while applications supply a database-specific atomic persistence operation.

Conceptually:

`AdvanceCounter(credentialID, matchedCounter) -> accepted | alreadyUsed | error`

The persistence operation must atomically check that `stored_counter < matched_counter` and, only when true, advance the stored counter to `matched_counter`. The check and update must be one indivisible operation.

Only one concurrent request should successfully advance a given stored counter to the same new value.

Advantages:

* gopasslib can provide a more misuse-resistant verification flow.
* Replay-prevention semantics remain consistent across applications.
* Applications can use their existing databases.
* Concurrent verification is protected when the storage implementation satisfies the contract.

Trade-offs:

* The library needs a clearly defined persistence interface.
* Applications must provide a correct atomic implementation.
* Credential lifecycle and transaction boundaries require careful consideration.

## 4. Persistence failures and authentication

Successful code verification should not automatically imply successful authentication.

If counter advancement fails, the authentication operation must not report success.

The design should distinguish between:

* An invalid TOTP code.
* A previously consumed counter.
* A persistence failure.

An ambiguous commit outcome also requires consideration. For example, a database update may succeed even if the caller experiences a timeout. Retrying the same code should not produce another successful authentication.

## 5. Interaction with other credential updates

The proposed design also supports password upgrades and other credential mutations.

If an application persists the entire serialized credential, a concurrent operation using an older credential snapshot could overwrite an updated TOTP counter.

Possible approaches include:

* Transactional credential updates.
* Version-based compare-and-swap.
* Separately maintained replay-prevention state.

The appropriate solution depends on the persistence contract chosen for gopasslib.

## 6. Additional considerations

### Enrollment and migration

The proposed protobuf field `uint64 last_used_counter = 8` defaults to zero when unset.

A non-optional protobuf scalar does not distinguish an unset value from an explicitly stored zero. The design should define initialization and migration semantics, potentially using field presence or an explicit initialization convention.

### Lookback periods

Codes from permitted earlier periods must still be rejected when their matching counters have already been consumed.

### Numeric code collisions

Different counters can occasionally produce identical numeric TOTP codes.

Returning the newest matching counter does not guarantee that the same numeric code can never be accepted again. This behavior should be considered when defining replay-prevention guarantees.

### Recovery and reset

Replacing a TOTP secret should have explicit replay-state initialization semantics.

## 7. Recommendation

A library-defined atomic persistence contract appears better aligned with gopasslib’s goal of providing a turnkey, misuse-resistant authentication API.

The application would remain responsible for implementing database-specific atomic operations, while gopasslib would coordinate verification and determine the authentication outcome.

This recommendation is intended for discussion before introducing public replay-prevention APIs or changing the protobuf schema.

## 8. Open questions

1. Should `Manager.VerifyTOTP()` coordinate atomic counter advancement, or should callers handle it explicitly?
2. Should atomic persistence be required whenever replay protection is enabled?
3. How should the proposed `OnUpgrade` callback interact with security-critical TOTP state updates?
4. Should `last_used_counter` remain inside the serialized credential or be maintained separately to simplify atomic updates?
5. What guarantees should be provided when persistence fails or the commit outcome is unknown?
