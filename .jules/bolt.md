## 2024-08-31 - String operations in loop or repeated calls
**Learning:** Found multiple repeated `strings.ToLower(name)` calls in a single function (`sendSecretView`) block. This evaluates the same `strings.ToLower(name)` up to 7 times.
**Action:** Store the result of `strings.ToLower(name)` in a local variable once, and use it for all subsequent `strings.Contains` checks.
