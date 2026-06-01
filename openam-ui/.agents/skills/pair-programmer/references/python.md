# Python Reference — Pair Programmer

## Idiomatic Python (Pythonic Patterns)

**Prefer comprehensions over loops for transformation:**
```python
# Avoid
result = []
for item in items:
    if item.active:
        result.append(item.name)

# Prefer
result = [item.name for item in items if item.active]
```

**Use `enumerate` instead of manual indexing:**
```python
for i, item in enumerate(items):  # not: for i in range(len(items))
    ...
```

**Use `zip` for parallel iteration; `zip_strict=True` (3.10+) to catch length mismatches.**

**Context managers for all resources:**
```python
with open(path) as f:           # files
with lock:                      # threading.Lock
async with aiohttp.ClientSession() as session:  # async I/O
```

**Dataclasses for value objects:**
```python
from dataclasses import dataclass, field

@dataclass(frozen=True)   # frozen = immutable
class Point:
    x: float
    y: float
```

---

## Type Hints

Always use type hints in new code. They're documentation that mypy/pyright can verify.

```python
from typing import Optional, Union
from collections.abc import Sequence, Mapping, Iterator

def process(items: Sequence[str], limit: int = 10) -> list[str]:
    ...

# Python 3.10+: use | instead of Union
def lookup(key: str) -> str | None:
    ...
```

**Common pitfalls:**
- `list[str]` not `List[str]` (3.9+)
- `str | None` not `Optional[str]` (3.10+)
- Don't annotate `self` or `cls`
- Use `Protocol` for structural typing (duck typing with static checks)

---

## Error Handling

**Be specific with exception types:**
```python
try:
    result = risky_operation()
except ValueError as e:
    logger.warning("Invalid input: %s", e)
    raise
except (ConnectionError, TimeoutError) as e:
    logger.error("Network failure: %s", e)
    raise RetryableError("upstream unavailable") from e
```

**Use `from e` for exception chaining — preserves traceback.**

**Never:**
```python
except Exception:
    pass  # silent swallow — catastrophic
except Exception as e:
    print(e)  # logging is not error handling
```

**Custom exceptions for domain errors:**
```python
class UserNotFoundError(ValueError):
    def __init__(self, user_id: int):
        super().__init__(f"User {user_id} not found")
        self.user_id = user_id
```

---

## Async Python

**Use `asyncio.gather` for concurrent I/O:**
```python
results = await asyncio.gather(fetch_a(), fetch_b(), fetch_c())
```

**Always handle cancellation:**
```python
try:
    result = await some_coroutine()
except asyncio.CancelledError:
    await cleanup()
    raise  # always re-raise CancelledError
```

**Don't block the event loop:**
- CPU-bound work → `asyncio.to_thread()` or `ProcessPoolExecutor`
- Sync I/O → `asyncio.to_thread()`
- Never: `time.sleep()`, `requests.get()`, or heavy computation in a coroutine

**Common traps:**
- Creating tasks but not awaiting them (fire-and-forget with no error handling)
- Mixing sync and async contexts (calling `async` function without `await`)
- Not using `async with` for async context managers

---

## Common Python Anti-Patterns

**Mutable default arguments:**
```python
def bad(items=[]):    # shared across calls!
def good(items=None):
    items = items or []
```

**Using `is` for value comparison:**
```python
if x is True:    # only True for the singleton
if x == True:    # compares value
if x:            # idiomatic for truthiness
```

**Bare `except` clause:**
```python
except:           # catches SystemExit, KeyboardInterrupt — never do this
except Exception: # minimum acceptable; still too broad usually
```

**Late binding closures in loops:**
```python
# Bug: all functions capture the same `i`
funcs = [lambda: i for i in range(5)]

# Fix: capture by default argument
funcs = [lambda i=i: i for i in range(5)]
```

**String concatenation in loops (O(n²)):**
```python
# Bad
result = ""
for s in strings:
    result += s

# Good
result = "".join(strings)
```

---

## Testing (pytest)

```python
# Arrange / Act / Assert
def test_user_creation():
    # Arrange
    repo = FakeUserRepo()
    service = UserService(repo)
    
    # Act
    user = service.create("alice@example.com")
    
    # Assert
    assert user.email == "alice@example.com"
    assert repo.get(user.id) == user

# Parametrize for multiple cases
@pytest.mark.parametrize("input,expected", [
    ("", []),
    ("a", ["a"]),
    ("a,b", ["a", "b"]),
])
def test_split(input, expected):
    assert split_csv(input) == expected

# Fixtures for setup/teardown
@pytest.fixture
def db():
    conn = create_test_db()
    yield conn
    conn.close()
```

**What to test:** behavior, not implementation. Test the public API. Don't mock what you own.

---

## Performance Traps

- `in` on a list is O(n) — use a `set` for membership checks on >10 items
- `.append()` in a loop is fine; `+=` on a list inside a loop is O(n²)
- `pandas` operations: avoid `iterrows()` — use vectorized ops or `apply()`
- SQLAlchemy: watch for N+1 — use `joinedload()` or `selectinload()`
- `re.compile()` outside the function if the pattern is reused

---

## Security Notes

- **SQL:** Never f-string into queries. Use parameterized queries (`cursor.execute(sql, params)`) or ORM
- **Shell:** Never `os.system(user_input)`. Use `subprocess.run([...], shell=False)`
- **File paths:** Use `pathlib.Path` and validate that paths don't escape the intended root (`path.resolve().is_relative_to(root)`)
- **Secrets:** Use `os.environ` or a secrets manager — never hardcode, never log
- **Pickle:** Never unpickle untrusted data (arbitrary code execution)
- **YAML:** Use `yaml.safe_load()`, never `yaml.load()` without Loader
