/* (C) 2005 by
 * Richard West (richard@dopplereffect.us)
 * Eric Mesa (djotaku1282@yahoo.com)
 * Lab 03 - Security System
 * Lab Date: 2 March 2005 
 * Published: 14 March 2005
 * Published under GNU General Public License - http://www.linux.org/info/gnu.html
 * http://www.ericsbinaryworld.com
 *
 * Hardware setup notes:
 *		Keypad connected to PortA.0-7
 *		LEDs connected to PortB.0-7
 *		LCD connected to PortC.0-7
 *		RS232 serial connection
 *
 * Optional features:
 *		Require a username and password instead of 4-digit code
 */

#define EXTRA_CREDIT

// Mega32 compiler directive
#include <Mega32.h>

// LCD compiler directives
#asm(".equ __lcd_port=0x15")
#include <lcd.h>

// keypad compiler direcive
#ifndef EXTRA_CREDIT
#define KEYPAD_TELPAD // using a telephone style keypad
#else
#define KEYPAD_KEYBOARD // using keypad as keyboard
#endif
#define KEYPAD_USEPORTA // wish to connect keypad to PortA
#define KEYPAD_USEDISPLAY // wish to use and LCD for display
#include "keypad.h"

// useful C libraries
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// door modes
#define DOOR_LOCKED 0x00
#define DOOR_LOCKOUT 0x01
#define DOOR_LOCKDOWN 0x02
#define DOOR_UNLOCKED 0x03
#define DOOR_OPEN 0x04

// door timing in seconds
#define DOOR_LOCKOUT_TIME 60
#define DOOR_UNLOCKED_TIME 10

// user modes
#define USER_NONE 0x00
#define USER_CODE 0x01
#define USER_NAME 0x02
#define USER_PASS 0x03
#define USER_CHECK 0x04
#define USER_DONE 0x05

// admin modes
#define ADMIN_WAIT 0x00
#define ADMIN_CMD 0x01

// runtime global variables
unsigned int timems;
unsigned int timeday;
#ifndef EXTRA_CREDIT
unsigned char* seccodes[8] =
	{"0000", "1234", "5678", "1357",
	 "2468", "1492", "1776", "1969"};
#else
unsigned char* usernames[4] =
	{"Richard", "Eric", "John", "Bruce"};
unsigned char* passwords[4] =
	{"happy", "binary", "TA", "Prof."};
unsigned char* userstr;
unsigned char* passstr;
#endif
unsigned char* nonestr = "none";
unsigned char codenum;
unsigned char timehour;
unsigned char timemin;
unsigned char timesec;
unsigned char timechanged;
unsigned char door_time; // in seconds
unsigned char keypad_time; // in milliseconds
unsigned char doormode;
unsigned char doormodechanged;
unsigned char usermode;
unsigned char usermodechanged;
unsigned char adminmode;
unsigned char attempts;
unsigned char r_index;
unsigned char r_ready;
unsigned char r_char;
unsigned char t_index;
unsigned char t_ready;
unsigned char t_char;
unsigned char lcd_buffer[16];
unsigned char r_buffer[32];
unsigned char t_buffer[32];
#ifdef EXTRA_CREDIT
unsigned char username[16];
unsigned char password[16];
#endif

// function prototype
void init(void);
void start(void);
void uart_receive(void);
void uart_send(void);

// timer0 compare interrupt service routine
interrupt [TIM0_COMP] void tim0_comp_isr(void)
{
	if(++timems == 1000)
	{
		timems = 0;
		if (++timesec == 60)
		{
			timesec = 0;
			if (++timemin == 60)
			{
				timemin = 0;
				if (++timehour == 24)
				{
					timehour = 0;
					if (++timeday == 365)
					{
						timeday = 0;
					}
				}
			}
		}
		
		// set timechanged flag
		timechanged = 0x01;

		// check door mode
		if ((doormode == DOOR_LOCKOUT) || (doormode == DOOR_UNLOCKED))
		{
			// increment door time
			door_time++;
		}
	}

	// check door mode
	if (doormode == DOOR_LOCKED)
	{
		// increment keypad time
		keypad_time++;
	}
}

// character ready interrupt service routine
interrupt [USART_RXC] void char_ready_isr(void)
{
	// get and echo the char
	r_char = UDR;
	UDR = r_char;
	if (r_char != '\r')
	{
		r_buffer[r_index++] = r_char;
	}
	else
	{
		// use putchar to avoid overwrite
		putchar('\n');

		// terminate string and signal ready
		r_buffer[r_index] = '\0';
		r_ready = 1;
		
		// stop isr
		UCSRB.7 = 0;
	}
}

// xmit empty interrupt service routine
interrupt [USART_DRE] void xmit_empty_isr(void)
{
	t_char = t_buffer[++t_index];
	if (t_char == '\0') 	
	{
		// kill isr and signal ready
		UCSRB.5 = 0;
		t_ready = 1;
	}
	else
	{
		// send the char
		UDR = t_char;
	}
}

void main(void)
{
	#ifndef EXTRA_CREDIT
	// map keypad buttons
	keypad_define_terminator('#');
	keypad_ignore_keysymbol('A');
	keypad_ignore_keysymbol('B');
	keypad_ignore_keysymbol('C');
	keypad_ignore_keysymbol('D');
	keypad_ignore_keysymbol('*');
	#endif

	lcd_init(16); // initialize LCD
	init(); // initialize MCU
	start(); // initialize security system

	// release the keypad
	keypad_release();

	// start uart receive
	uart_receive();

	while(1)
	{
		// check admin mode
		if (adminmode == ADMIN_WAIT)
		{
			if (r_ready)
			{
				// change admin mode
				adminmode = ADMIN_CMD;
			}
		}
		else if (adminmode == ADMIN_CMD)
		{
			// extract first character of receive buffer
			unsigned char c;
			c = r_buffer[0];

			// check for command code
			if (c == 'c')
			{
				#ifndef EXTRA_CREDIT
				// extract code changes
				sscanf(r_buffer, "c %u", &codenum);
				strncpy(seccodes[codenum], r_buffer+4, 4);
				#else
				// needs to be changed !!!
				sscanf(r_buffer, "c %u %s %s", &codenum, &userstr, &passstr);
				strcpy(usernames[codenum], userstr);
				strcpy(passwords[codenum], passstr);
				#endif
			}
			else if (c == 'd')
			{
				// extract code to delete
				sscanf(r_buffer, "d %u", &codenum);
				#ifndef EXTRA_CREDIT
				strcpy(seccodes[codenum], nonestr);
				#else
				strcpy(usernames[codenum], nonestr);
				strcpy(passwords[codenum], nonestr);
				#endif
			}
			else if (c == 'h')
			{
				// display help on the PC
			}
			else if (c == 'l')
			{
				if (doormode == DOOR_LOCKED)
				{
					// lockdown the door
					doormode = DOOR_LOCKDOWN;
					usermode = USER_DONE;
				}
				else if (doormode == DOOR_OPEN)
				{
					// lock the door
					doormode = DOOR_LOCKED;
					usermode = USER_NONE;
				}
				doormodechanged = 0x01;
				usermodechanged = 0x01;
			}
			else if (c == 's')
			{
				unsigned char i;

				// show all codes
				#ifndef EXTRA_CREDIT
				for (i=0; i<8; i++)
				#else
				for (i=0; i<4; i++)
				#endif
				{
					// spin-lock
					while(!t_ready);

					// load buffer and send
					#ifndef EXTRA_CREDIT
					sprintf(t_buffer, "%u) %s\r\n", i, seccodes[i]);
					#else
					sprintf(t_buffer, "%u) %s %s\r\n", i, usernames[i], passwords[i]);
					#endif
					uart_send();
				}
			}
			else if (c == 't')
			{
				// extract new time
				sscanf(r_buffer, "t %d %u %u", &timeday, &timehour, &timemin);
				timesec = 0;
				timechanged = 0x01;
			}
			else if (c == 'u')
			{
				if (doormode == DOOR_LOCKED)
				{
					// open the door
					doormode = DOOR_OPEN;
					usermode = USER_DONE;
				}
				else if (doormode == DOOR_LOCKDOWN)
				{
					// lock the door
					doormode = DOOR_LOCKED;
					usermode = USER_NONE;
				}
				doormodechanged = 0x01;
				usermodechanged = 0x01;
			}
			else if (c == 'x')
			{
				// clear the PC screen
				// spin-lock
				while(!t_ready);

				sprintf(t_buffer, "\f");
				uart_send();
			}

			// change admin mode
			adminmode = ADMIN_WAIT;

			// restart uart receive
			uart_receive();
		}

		// check door mode
		if (doormode == DOOR_LOCKED)
		{
			// check keypad_time
			if (keypad_time == 30)
			{
				// reset keypad_time
				keypad_time = 0x00;

				// get keystring
				keypad_get_string();
			}

			// check user mode
			if (usermode == USER_NONE)
			{
				if (usermodechanged || timechanged)
				{
					// reset change flags
					timechanged = 0x00;
					usermodechanged = 0x00;

					// release the keypad
					keypad_release();

					// format time string
					sprintf(lcd_buffer, "time: %02u:%02u.%02u", timehour, timemin, timesec);

					// display time string
					lcd_clear();
					lcd_gotoxy(0,0);
					lcd_puts(lcd_buffer);

					// display prompt
					lcd_gotoxy(0,1);
					lcd_putsf("# to login");
				}
				else if (keystring_ready)
				{
					// change user mode
					#ifndef EXTRA_CREDIT
					usermode = USER_CODE;
					#else
					usermode = USER_NAME;
					#endif
					usermodechanged = 0x01;
				}
			}
			#ifndef EXTRA_CREDIT
			else if (usermode == USER_CODE)
			{
				if (usermodechanged)
				{
					// reset usermodechanged flag
					usermodechanged = 0x00;

					// release the keypad
					keypad_release();

					// display prompt
					lcd_clear();
					lcd_gotoxy(0,0);
					lcd_putsf("Enter code:");

					// setup keypad display
					keypad_set_display(KEYPAD_MASKDISPLAY);
					keypad_gotoxy(0,1);
				}
				else if (keystring_ready)
				{
					// change user mode
					usermode = USER_CHECK;
					usermodechanged = 0x01;
				}
			}
			else if (usermode == USER_CHECK)
			{
				if (usermodechanged)
				{
					unsigned char i;

					// reset usermodechanged flag
					usermodechanged = 0x00;

					for (i=0; i<8; i++)
					{
						if (!strcmp(keystring, seccodes[i]))
						{
							// spin-lock
							while (!t_ready);

							// load buffer and send
							sprintf(t_buffer, "%u:%u:%u %s (good)\r\n", timeday, timehour, timemin, keystring);
							uart_send();

							// unlock the door
							doormode = DOOR_UNLOCKED;
							doormodechanged = 0x01;

							// change user mode
							usermode = USER_DONE;
							usermodechanged = 0x01;

							// display good news
							lcd_clear();
							lcd_gotoxy(0,0);
							lcd_putsf("unlocked");

							break;
						}
					}

					// if invalid entry
					if (doormode != DOOR_UNLOCKED)
					{
						// spin-lock
						while (!t_ready);

						// load buffer and send
						sprintf(t_buffer, "%u:%u:%u %s (bad)\r\n", timeday, timehour, timemin, keystring);
						uart_send();

						if (++attempts == 3)
						{
							// lockout the door
							doormode = DOOR_LOCKOUT;
							doormodechanged = 0x01;

							// change user mode
							usermode = USER_DONE;
							usermodechanged = 0x01;

							// display bad news
							lcd_clear();
							lcd_gotoxy(0,0);
							lcd_putsf("lockout");
						}
						else
						{
							// release keypad
							keypad_release();

							// display okay news
							lcd_clear();
							lcd_gotoxy(0,0);
							lcd_putsf("locked");

							// display prompt
							lcd_gotoxy(0,1);
							lcd_putsf("# to login");
						}
					}
				}
				else if (keystring_ready)
				{
					// change user mode
					usermode = USER_CODE;
					usermodechanged = 0x01;
				}
			}
			#else
			else if (usermode == USER_NAME)
			{
				if (usermodechanged)
				{
					// reset usermodechanged flag
					usermodechanged = 0x00;

					// release the keypad
					keypad_release();

					// display prompt
					lcd_clear();
					lcd_gotoxy(0,0);
					lcd_putsf("Username:");

					// setup keypad display
					keypad_set_display(KEYPAD_ECHODISPLAY);
					keypad_gotoxy(0,1);
				}
				else if (keystring_ready)
				{
					// if string is different from "none"
					if (strcmp(keystring, nonestr))
					{
						// store username
						strcpy(username, keystring);

						// change user mode
						usermode = USER_PASS;
						usermodechanged = 0x01;
					}
					else
					{
						// change user mode
						usermode = USER_NONE;
						usermodechanged = 0x01;
					}
				}
			}
			else if (usermode == USER_PASS)
			{
				if (usermodechanged)
				{
					// reset usermodechanged flag
					usermodechanged = 0x00;

					// release the keypad
					keypad_release();

					// display prompt
					lcd_clear();
					lcd_gotoxy(0,0);
					lcd_putsf("Password:");

					// setup keypad display
					keypad_set_display(KEYPAD_MASKDISPLAY);
					keypad_gotoxy(0,1);
				}
				else if (keystring_ready)
				{
					// store password
					strcpy(password, keystring);

					// change user mode
					usermode = USER_CHECK;
					usermodechanged = 0x01;
				}
			}
			else if (usermode == USER_CHECK)
			{
				if (usermodechanged)
				{
					unsigned char i;

					// reset usermodechanged flag
					usermodechanged = 0x00;

					for (i=0; i<4; i++)
					{
						if (!strcmp(username, usernames[i]))
						{
							if (!strcmp(password, passwords[i]))
							{
								// spin-lock
								while (!t_ready);

								// load buffer and send
								sprintf(t_buffer, "%u:%u:%u %s (good)\r\n", timeday, timehour, timemin, username);
								uart_send();

								// unlock the door
								doormode = DOOR_UNLOCKED;
								doormodechanged = 0x01;

								// change user mode
								usermode = USER_DONE;
								usermodechanged = 0x01;

								// display good news
								lcd_clear();
								lcd_gotoxy(0,0);
								lcd_putsf("unlocked");
							}

							break;
						}
					}

					// if invalid entry
					if (doormode != DOOR_UNLOCKED)
					{
						// spin-lock
						while (!t_ready);

						// load buffer and send
						sprintf(t_buffer, "%u:%u:%u %s (bad)\r\n", timeday, timehour, timemin, username);
						uart_send();

						if (++attempts == 3)
						{
							// lockout the door
							doormode = DOOR_LOCKOUT;
							doormodechanged = 0x01;

							// change user mode
							usermode = USER_DONE;
							usermodechanged = 0x01;

							// display bad news
							lcd_clear();
							lcd_gotoxy(0,0);
							lcd_putsf("lockout");
						}
						else
						{
							// release keypad
							keypad_release();

							// display okay news
							lcd_clear();
							lcd_gotoxy(0,0);
							lcd_putsf("locked");

							// display prompt
							lcd_gotoxy(0,1);
							lcd_putsf("# to login");
						}
					}
				}
				else if (keystring_ready)
				{
					// change user mode
					usermode = USER_NAME;
					usermodechanged = 0x01;
				}
			}
			#endif
		}
		else if (doormode == DOOR_LOCKDOWN)
		{
			if (doormodechanged)
			{
				// reset doormodechanged flag
				doormodechanged = 0x00;

				// display lockdown message
				lcd_clear();
				lcd_gotoxy(0,0);
				lcd_putsf("lockdown");
			}
		}
		else if (doormode == DOOR_OPEN)
		{
			if (doormodechanged)
			{
				// reset doormodechanged flag
				doormodechanged = 0x00;

				// display open message
				lcd_clear();
				lcd_gotoxy(0,0);
				lcd_putsf("open");
			}
		}
		else if (((doormode == DOOR_LOCKOUT) && (door_time == DOOR_LOCKOUT_TIME)) || 
			((doormode == DOOR_UNLOCKED) && (door_time == DOOR_UNLOCKED_TIME)))
		{
			// reset door time
			door_time = 0;

			// change door mode
			doormode = DOOR_LOCKED;
			doormodechanged = 0x01;

			// change user mode
			usermode = USER_NONE;
			usermodechanged = 0x01;

			// reset attempts
			attempts = 0;
		}
	}
}

void init(void)
{
	// initialize ports
	DDRA = 0x00; // set portA as input
	DDRB = 0xFF; // set portB as output
	DDRD = 0x00; // set portD as input
	PORTB = 0xFF; // turn off all LEDs

	// setup timer0
	// 16 MHz system clock
	// Prescaler = 64 -> 250 kHz timer
	TIMSK = 0x02; // enable the timer0 compare interrupt
	OCR0 = 0xF9; // set compare register to 249 (250 ticks = 1ms)
	TCCR0 = 0x0B; // set prescaler and clear-on-match

	// setup serial port
	UCSRB = 0x18;
	UBRRL = 0x67;
	putsf("\r\nStarting...\r\n");
	r_ready = 0x00;
	t_ready = 0x01;

	// enable interrupts
	#asm("sei")
}

void start(void)
{
	// reset times
	door_time = 0;
	keypad_time = 0;

	// change door mode
	doormode = DOOR_LOCKED;
	doormodechanged = 0x01;

	// change user mode
	usermode = USER_NONE;
	usermodechanged = 0x01;

	// reset attempts
	attempts = 0;
}

void uart_receive(void)
{
	r_ready = 0x00;
	r_index = 0x00;
	UCSRB.7 = 0x01;
}

void uart_send(void)
{
	t_ready = 0x00;
	t_index = 0x00;
	if (t_buffer[0] > '\0')
	{
		putchar(t_buffer[0]);
		UCSRB.5 = 0x01;
	} 
}
