# CELF: postęp pierwszej rundy i optymalizacja batchy

## 1. Raportowanie pierwszej rundy

`_GpuScorer.score_exact_batch()`, `score_batch()` i `_score_single_recording()`
przyjmują opcjonalny `progress_callback`. Callback aktualizuje pasek i emituje
trwały heartbeat co 8 sekund. Licznik `selected/N` nadal rośnie dopiero po
zatwierdzeniu zwycięzcy; praca wewnątrz rundy jest raportowana osobno.

Pasek CELF ma krótszy opis. Przy wąskim terminalu renderer skraca wizualny
prefiks, ale zachowuje końcowe pola diagnostyczne `gpu_dispatches` i
`rescored`. Po zakończeniu pierwszej rundy loguje czas, indeks zwycięzcy,
liczbę dispatchów GPU i liczbę przeliczonych challengerów.

## 2. Batchowanie i dispatches

- Domyślny `RANKER_GREEDY_RESCORE_BATCH` wynosi teraz 256 (wcześniej 128).
- Domyślny `RANKER_EXACT_BATCH` wynosi teraz 128 (wcześniej 64).
- Oba batch'e są ograniczane przez `rule_batch_size` i
  `MAX_DISPATCH_ITEMS / max_chunk_words`, aby typowo pozostać pojedynczym
  legalnym kernelem na word-chunk.
- `RANKER_EXACT_BATCH` jest dodatkowo ograniczany do 256, bo lokalny identyfikator
  reguły w skompaktowanym strumieniu wyników ma typ `uint8`.
- Grupowanie exact challengerów przegląda ograniczone okno do 4x limitu batcha.
  Nieświeże wpisy kopca są odkładane i przywracane, a świeże challengery mogą
  być dokładnie przeliczane razem, nawet jeśli nie leżą bezpośrednio obok siebie
  w kopcu. Obliczenia nie zmieniają aktywnego zbioru, więc kolejność sprawdzania
  exact gain nie zmienia kryterium zwycięzcy ani tie-breaku.

## 3. Bezkolizyjny zapis exact wyników i transfer GPU -> CPU

`score_exact_batch_kernel` zapisuje wynik każdej pary `(reguła, słowo)` pod
własnym indeksem w macierzy `uint32` w układzie rule-major. Brak trafienia jest
oznaczany przez `UINT32_MAX`. Kernel nie używa globalnego licznika `atomic_add`
ani wspólnego append-bufora, więc zapisy różnych reguł nie konkurują o jeden
adres pamięci.

Host pobiera jeden zwarty blok D2H dla całego batcha. Wiersze są już pogrupowane
według reguły; nie ma dodatkowego bufora identyfikatorów reguł ani globalnego
`np.argsort`. W każdym wierszu sentinel jest odfiltrowywany, a końcowe
`np.unique` nadal deduplikuje sloty dla danej reguły przez wszystkie word-chunki.
Dokładny gain i deterministyczny tie-break CELF pozostają niezmienione.

Kosztem jest transfer macierzy `n_rules x n_words` także wtedy, gdy część
par nie trafia w aktywny TARGET. Dla typowego pierwszego przebiegu, w którym
najwyżej oceniane reguły mają niemal pełne trafienia, stały transfer jest
porównywalny lub mniejszy od poprzedniego strumienia slotów + identyfikatorów,
a usuwa koszt globalnej kontencji atomowej i sortowania wyników na CPU.
Profil `exact-result D2H` raportuje teraz jedną kopię macierzy na word-chunk,
liczbę przesłanych MiB oraz liczbę niepustych wierszy reguł; nie ma odczytu
licznika trafień.

## 4. Liczniki GPU

`gpu_dispatches` zlicza teraz rzeczywiste wywołania kernel launch w operacjach
CELF: singleton exact, batch tighten, exact batch oraz zastosowanie zwycięzcy.
Raport profilu podaje łączną liczbę `gpu_kernel_dispatches`. Dzięki temu nowy
pomiar można porównać z wcześniejszymi licznikami, które odzwierciedlały wywołania
metod scoringowych, a nie zawsze rzeczywistą liczbę kernel launchy.

## Weryfikacja

- Pełny `pytest -q`: **565 passed, 5 skipped**.
- Źródło OpenCL wygenerowane przez `get_recompute_kernel_source()` przechodzi
  kontrolę składni `clang -x cl -cl-std=CL1.2 -fsyntax-only`.
- Integracyjny test GPU jest pominięty, ponieważ środowisko testowe nie ma
  runtime OpenCL.
- Nie wykonano benchmarku na RTX 3060 Ti. Nowe wartości batchy i globalny append
  trzeba potwierdzić na tej karcie; testy jednostkowe nie dowodzą przyspieszenia.

## Zalecany pomiar na RTX 3060 Ti

Wykonać ten sam dataset z profilem włączonym i zachować te same `rules-file`,
`wordlist`, `cracked`, `budgets` i parametry CLI. Porównać `gpu_kernel_dispatches`,
czas `fresh_resolve_exact_batch`, `batch_tighten`, `exact-result D2H`, całkowity
czas CELF, VRAM i pokrycie. W razie presji pamięci lub pogorszenia czasu można
ustawić `RANKER_EXACT_BATCH=64` i/lub `RANKER_GREEDY_RESCORE_BATCH=128`.
