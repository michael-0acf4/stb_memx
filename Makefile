CC = gcc

example_target:
	$(CC) examples/i32_not_a_game.c -o not_a_game
	./not_a_game

example_editor:
	$(CC) examples/i32_memx_editor.c -o editor
	./editor