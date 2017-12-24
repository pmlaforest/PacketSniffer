#include <windows.h> 

HANDLE hStdout, hStdin;
CONSOLE_SCREEN_BUFFER_INFO csbiInfo;

void set_cursor_to_previous_line(int negative_offset)
{
	COORD curr_cursor_pos;
	COORD new_cursor_pos;

	hStdin = GetStdHandle(STD_INPUT_HANDLE);
	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdin == INVALID_HANDLE_VALUE ||
		hStdout == INVALID_HANDLE_VALUE)
	{
		MessageBox(NULL, TEXT("GetStdHandle"), TEXT("Console Error"),
			MB_OK);
		return 1;
	}

	if (!GetConsoleScreenBufferInfo(hStdout, &csbiInfo))
	{
		MessageBox(NULL, TEXT("GetConsoleScreenBufferInfo"),
			TEXT("Console Error"), MB_OK);
		return 1;
	}

	curr_cursor_pos = csbiInfo.dwCursorPosition;

	// Set the new cursor's position
	new_cursor_pos.X = 0;
	new_cursor_pos.Y = curr_cursor_pos.Y - negative_offset;


	if (!SetConsoleCursorPosition(hStdout, new_cursor_pos))
	{
		MessageBox(NULL, TEXT("SetConsoleCursorPosition"),
			TEXT("Console Error"), MB_OK);
		return 1;
	}
}
