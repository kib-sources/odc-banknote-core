# odc-banknote-core

Код на Си, работающий с банкнотами, включая odcb файлы

Ядро по работе с банкнотами ODC,
с файлами расширения `.odcb`.

Ядро написано на чистом Си
и имеет мосты с языками программирования:
1. C++
2. Java
3. Python
4. Go
5. Kotlin
5. RUST
6. C#


Описание работы протокола: ...

## Сборка проекта 
### Linux 

В корне проекта создаём папку `build`:

```bash
~$ cmake -S . -B build
```

После можно собрать проект:

```bash
~$ cmake --build build
```

Для запуска тестов:

```bash
~$ ctest --test-dir build/

Internal ctest changing into directory: ~/build
Test project ~/build
    Start 1: test_a
1/2 Test #1: test_a ...........................   Passed    0.39 sec
    Start 2: test_b
2/2 Test #2: test_b ...........................   Passed    0.00 sec

100% tests passed, 0 tests failed out of 2

Total Test time (real) =   0.39 sec
```

### Windows
(Not supported yet)