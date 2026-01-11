CC = gcc
OPT = -O3

example_target:
	$(CC) examples/i32_not_a_game.c -o not_a_game $(OPT)
	./not_a_game

example_editor:
	$(CC) examples/i32_memx_editor.c -o editor $(OPT)
	./editor
