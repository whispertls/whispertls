import logging
import curses
import threading
import regex
import locale
import traceback
from wcwidth import wcswidth
from whispertls.MasterKey import MasterKey

class NcursesUI:
    def __init__(self,main_app = None):
        locale.setlocale(locale.LC_ALL, '') 
        self.main_app = main_app
        self.main_win = None
        self.input_win = None
        self.input_text = ""
        self.running = False
        self.main_content  = []
        self.selected_contact = None
        self.is_lock = False
        self.is_passwordprotected = False

    def function_debug(self):
        self.main_app.debug()
        

    def function_list(self):
        contacts = self.main_app.get_contacts()
        if contacts:
            for i, contact in enumerate(contacts):
                line = f"{contact['id']} - {contact['nickname']}"
                self.add_message(line)
        else:
            self.add_message("NcursesUI: There is no contacts to show")

    def function_select(self,args):
        if len(args) < 1:
            self.add_message("Usage: /select <contact_id>")
            return
        contact_id = args[0].strip()
        if self.main_app.is_valid_contact(contact_id):
            self.selected_contact = contact_id
            messages = self.main_app.get_messages(self.selected_contact,0)
            for message in messages:
                line = "{} {}".format("->" if (message['direction'] == "recv")  else "<-" ,message['msg'])
                self.add_message(line)                
        else:
            self.add_message("The selected contact doesn't exist, check /list")

    def function_add(self,args):
        if len(args) < 1:
            self.add_message("Usage: /add <oob_string>")
            return
        oob_string = args[0]
        code = self.main_app.add_contact(oob_string)
        if code:
            self.add_message("First OOB Step success, give this code to your contact {}".format(code['partial']))
        else:
            self.add_message("Something went wrong please retry the process again")

    def function_set(self,args):
        if len(args) < 2:
            self.add_message("Usage: /set <key> <value>")
            return
        #self.add_message("Setting {} :{}".format(args[0],args[1]))
        code = self.main_app.set_config(args[0],args[1])
        #if code:
        #    self.add_message("First OOB Step success, give this code to your contact {}".format(code['partial']))
        #else:
        #    self.add_message("Something went wrong please retry the process again")

    def function_oob(self):
        oob_data = self.main_app.oob_start_request()
        self.add_message("Give this code to your contact: {}".format(oob_data))
        self.add_message("That CODE is ephemeral/temporary, only works ONCE, if the process fail you need to start over /oob")

    def function_delete(self,args):
        if len(args) < 1:
            self.add_message("Usage: /delete <contact_id>")
            return
        contact_id = args[0]
        result = self.main_app.delete_contact(contact_id)
        if result:
            self.add_message("contact deleted successfully")
        else:
            self.add_message("something happen, pleasy retry")

    def function_setpassword(self):
        if self.is_passwordprotected:
            self.add_message("The password is already set")
        else:
            pwd1 = self.function_getpassword("Password")
            pwd2 = self.function_getpassword("Verify password")
            self.clear_messages()
            if pwd1 == pwd2:
                if self.main_app.set_password(pwd1):
                    self.add_message("Success, password was set properly")
                    self.is_passwordprotected = True
                    self.is_lock = False
                    self.main_app.login(pwd1)
                else:
                    self.add_message("Fail, something fail, password wasn't set")
            else:
                self.add_message("Password doesn't match")

    def function_changepassword(self):
        old = self.function_getpassword("Old Password")
        pwd1 = self.function_getpassword("New password")
        pwd2 = self.function_getpassword("Verify new password")
        if (pwd1 != pwd2):
            self.add_message("Password mismatch")
            return
        if self.main_app.change_password(old,pwd1):
            self.add_message("Password was changed, succesfully")
        else :
            self.add_message("Old password is wrong")

    def function_verify(self,args):
        if len(args) < 1:
            self.add_message("Usage: /verify <code>")
            return
        result = self.main_app.verify(args[0])
        if result:
            self.add_message("Contact {} added succesfully".format(result['contact_id']))
            self.add_message("Set nickname with command /nick <contact_id> <nickname>")
        else:
            self.add_message("ERROR, something fails, please check if the code is corrrect or start the process again")

    def function_exit(self):
        self.main_app.shutdown()

    def function_search(self,args):
        if len(args) < 1:
            self.add_message("Usage: /search <keyword>")
            return
        # Call self.main_app.sea(keyword)
        keyword = args[0]
        results = self.main_app.search_messages(keyword)
        if results:
            self.display_search_results(results)
        else:
            self.add_message("There is no result for this search")

    def function_nick(self,args):
        if len(args) < 2:
            self.add_message("Usage: /nick <contact_id> <nickname>")
            return
        r = self.main_app.set_nick(args[0].strip(),args[1].strip())
        if r:
            self.add_message("Succcess new nick {} for contact {}".format(args[1],args[0]))
        else:
            self.add_message("Something went wrong")

    def function_lock(self):
        self.clear_messages()
        self.add_message("NcursesUI: System is locked please do /login")
        self.is_lock = True
        self.selected_contact = None
        
    def function_getpassword(self,prompt,cover_char = '*'):
        height, width = self.stdscr.getmaxyx()
        subwin_height = 3
        subwin_width = 40
        subwin_y = (height // 2) - 1
        subwin_x = (width // 2) - (subwin_width // 2)
        subwin = curses.newwin(subwin_height, subwin_width, subwin_y, subwin_x)
        covered = ""
        password = ""
        index = 0
        graphemes = []
        while True:
            subwin.clear() 
            subwin.box()
            subwin.addstr(1, 1, "{}: {}".format(prompt,covered))
            subwin.refresh()
            key = subwin.get_wch()
            cluster = regex.findall(r"\X",key)[0]
            if key == "\n":
                break
            elif key == "\x1b":
                graphemes = []
                break
            elif key == "\b" or key == "\x7f":
                if index > 0:
                    index += -1
                    graphemes = graphemes[:-1]
                    covered = covered[:-1]
            else:
                graphemes.append(cluster)
                covered += cover_char
                index += 1
        password = ''.join(graphemes)
        subwin.clear() 
        subwin.refresh()
        return password

    def function_login(self):
        password = self.function_getpassword("Password")
        #self.clear_messages()
        if self.main_app.login(password):
            self.is_lock = False
            self.add_message("NcursesUI: System is unlocked!")
        else:
            self.add_message("NcursesUI: Wrong password please try again")
    
    def function_reset(self):
        if self.main_app.reset_network():
            self.add_message("NcursesUI: Resetting network Circuits")
        else:
            self.add_message("NcursesUI: Something went wrong, network not reset, please try again")
    
    def function_status(self):
        status = self.main_app.get_status()
        if status:
            self.add_message("Application Status")
            for k, v in status.items():
                self.add_message("{} : {}".format(k,v))
        else:
            self.add_message("Something went wrong we can't retreive the the current status")
        
    def function_hs(self):
        services = self.main_app.list_hs()
        if services:
            for hs in services:
                line = "{} - {} - {}".format(hs["service_id"],hs["tor_port"],hs["os_port"])
                self.add_message(line)
        else:
            self.add_message("NcursesUI: There is no current HS to show")
    
    def handle_command(self, command_str: str):
        try:
            parts = command_str.strip().split()
            if not parts:
                return
            cmd = parts[0][1:].lower()
            args = []
            if len(parts) > 1:
                args = parts[1:]
            
            if self.is_lock:
                if cmd == "login":
                    self.function_login()
                    return
                elif cmd == "exit" or cmd == "quit":
                    self.function_exit()
                    return
                elif cmd == "set":
                    self.function_set(args)
                    return
                return
            
            if cmd == "list":
                self.function_list()
                return
            elif cmd == "select":
                self.function_select(args)
                return
            elif cmd == "add":
                self.function_add(args)
                return
            elif cmd == "oob":
                self.function_oob()
                return
            elif cmd == "delete":
                self.function_delete(args)
                return
            elif cmd == "setpassword":
                self.function_setpassword()
                return
            elif cmd == "changepassword":
                self.function_changepassword()
                return
            elif cmd == "lock":
                self.function_lock()
                return
            elif cmd == "reset":
                self.function_reset()
                return
            elif cmd == "clear":
                self.clear_messages()
                return
            elif cmd == "status":
                self.function_status()
                return
            elif cmd == "help":
                self.show_help()
                return
            elif cmd == "config":
                self.function_config()
                return
            elif cmd == "search":
                self.function_search(args)
                return
            elif cmd == "verify":
                self.function_verify(args)
                return
            elif cmd == "exit" or cmd == "quit":
                self.function_exit()
                return
            elif cmd == "nick":
                self.function_nick(args)
                return
            elif cmd == "set":
                self.function_set(args)
                return
            elif cmd == "hs":
                self.function_hs()
                return
            elif cmd == "debug":
                self.function_debug()
                return
            else:
                self.add_message(f"Unknown command: /{cmd}")
        except Exception as e:
            self.add_message(f"handle_command: Error: {str(e)}")
            tb = e.__traceback__
            for frame in traceback.extract_tb(tb):
                errorline = "{} {} {} {}".format(frame.filename, frame.lineno, frame.name, frame.line)
                self.add_message(errorline)
        
    def start(self):
        if self.main_app.existsmasterkey():
            self.is_passwordprotected = True
        curses.wrapper(self._init_ui)
   
    def clear_messages(self):
        self.main_content = []
        self.main_win.clear()
        self.main_win.refresh()
    
    def _init_ui(self, stdscr):
        stdscr.clear()
        self.stdscr = stdscr
        height, width = stdscr.getmaxyx()
        main_height = height - 1
        input_height = 1
        self.main_win = curses.newwin(main_height, width, 0, 0)
        self.input_win = curses.newwin(input_height, width, main_height, 0)
        self.main_win.keypad(True)
        self.input_win.keypad(True)
        if curses.has_colors():
            curses.start_color()
            curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)
            self.main_win.bkgd(' ', curses.color_pair(1))
            self.input_win.bkgd(' ', curses.color_pair(2)) 
        self.running = True
        self._main_loop()
    
    def _main_loop(self):
        self._draw_ui()
        if self.is_passwordprotected:
            self.is_lock = True
            self.add_message("NcursesUI: System is locked please do /login")
        else:
            self.add_message("NcursesUI: password is not set plesae do /setpassword")
        while self.running:
            try:
                msg = self.get_input(">")
                self.clear_input(">")
                if not msg:
                    continue
                msg = msg.strip()
                if msg[0] == '/':
                    self.handle_command(msg)
                else:
                    if self.selected_contact:
                        self.main_app.send_text_message(self.selected_contact,msg)
                        #self.add_message("<- {}".format(msg))
                    else:
                        self.add_message("NcursesUI: first select a contact to talk")
                        self.add_message("NcursesUI: /list")
                        self.add_message("NcursesUI: /select <contact_id>")
                        self.add_message("NcursesUI: /help to see full command list")
            except KeyboardInterrupt:
                self.add_message(f"KeyboardInterrupt Error: {str(e)}")
                self.running = False
            except Exception as e:
                self.add_message(f"Exception Error: {str(e)}")
                self.running = False
        self.clear_messages()
        if self.main_win:
            self.main_win.clear()
        if self.input_win:
            self.input_win.clear()
        curses.endwin()

    def clear_input(self,prompt):
        self.input_text = ""
        self.input_win.clear()
        self.input_win.addstr(0, 0, prompt)
        self.input_win.refresh()
        

    def get_input(self,prompt):
        try:
            self.input_text = ""
            self.input_win.clear()
            self.input_win.addstr(0, 0, prompt)
            self.input_win.refresh()
            graphemes = []
            widths = []
            array_size = 0
            array_index = 0
            offset = wcswidth(prompt) 
            cursor_x = 0
            inputlen = 0
            self.input_win.move(0, offset + cursor_x)  
            while True:
                key = self.input_win.get_wch()
                if isinstance(key,str):
                    if key == "\n": #Enter
                        break
                    cluster = regex.findall(r"\X",key)[0]
                    wcs = wcswidth(cluster)
                    if wcs >= 1:
                        graphemes.insert(array_index,cluster)
                        widths.insert(array_index,wcs)
                        array_size += 1
                        array_index += 1
                        self.input_text = ''.join(graphemes)
                        self.input_win.addstr(0, offset , self.input_text)
                    #else:
                        #self.add_message("Ignorig key with width size less than 1: {} {}".format(cluster,wcs))
                    if(array_index != array_size):
                        cursor_x = sum(widths[:array_index])
                    else:
                        cursor_x = sum(widths[:array_size])
                else:
                    if key == 10: #Enter
                        break
                    elif key == 8 or key == 263 or key == 127 or key == curses.KEY_BACKSPACE:  # Backspace
                        #self.add_message("{} {} {}".format(array_index,array_size,cursor_x))
                        if array_index > 0:
                            array_index -= 1
                            cursor_x = sum(widths[:array_size])
                            array_size -= 1
                            del graphemes[array_index]
                            del widths[array_index]
                            self.input_text = ''.join(graphemes)
                            self.input_win.addstr(0, offset , ' ' * cursor_x) 
                            self.input_win.addstr(0, offset , self.input_text)
                            if(array_index != array_size):
                                cursor_x = sum(widths[:array_index])
                            else:
                                cursor_x = sum(widths[:array_size])
                        elif key == 330 or key == curses.KEY_DC: # DELETE
                            if array_index < array_size:
                                cursor_x = sum(widths[:array_size])
                                del graphemes[array_index]
                                del widths[array_index]
                                array_size -= 1
                                self.input_text = ''.join(graphemes)
                                self.input_win.addstr(0, offset , ' ' * cursor_x) 
                                self.input_win.addstr(0, offset , self.input_text)
                                if(array_index != array_size):
                                    cursor_x = sum(widths[:array_index])
                                else:
                                    cursor_x = sum(widths[:array_size])
                        elif key == 262:  #  Home
                            cursor_x = 0
                        elif key == 360:  #  end
                            cursor_x = sum(widths[:array_size])
                        elif key == curses.KEY_LEFT:
                            #self.add_message("{} {} {}".format(array_index,array_size,cursor_x))
                            if array_index > 0:
                                array_index -= 1
                                cursor_x = sum(widths[:array_index])
                        elif key == curses.KEY_RIGHT:
                            #self.add_message("{} {} {}".format(array_index,array_size,cursor_x))
                            if array_index < array_size:
                                array_index += 1
                                cursor_x = sum(widths[:array_index])
                        else:
                            graphemes.insert(array_index,chr(key))
                            widths.insert(array_index,wcswidth(chr(key)))
                            array_size += 1
                            array_index += 1
                            self.input_text = ''.join(graphemes)
                            self.input_win.addstr(0, offset , self.input_text)
                            if(array_index != array_size):
                                cursor_x = sum(widths[:array_index])
                            else:
                                cursor_x = sum(widths[:array_size])
                self.input_win.move(0, offset + cursor_x)
                self.input_text = ''.join(graphemes)
            return self.input_text
        except KeyboardInterrupt as e:
            self.add_message(f"get_input: KeyboardInterrupt: {e}")
            self.running = False
        except Exception as e:
            self.add_message(f"get_input: Error: {e}")

    def _draw_ui(self):
        self.main_win.clear()
        self.input_win.clear()
        self.main_win.refresh()
        self.input_win.refresh()

    def add_message(self, message: str):
        if not self.main_win:
            return
        try:
            self.main_win.clear()
            self.main_content.append(message)
            max_rows, max_cols = self.main_win.getmaxyx()
            num_lines_to_show = max_rows - 1
            start_idx = max(0, len(self.main_content) - num_lines_to_show)
            lines_to_show = self.main_content[start_idx:]
            for i,line in enumerate(lines_to_show):
                self.main_win.addstr(i,0,line)
            self.main_win.refresh()
        except Exception as e:
            self.running = False
            print("add_message",e)

    def show_help(self):
        lines = [
            "/help                         - Show this list",
            "/list                         - Show the contact list",
            "/select <contact_id>          - Start a conversation with the selected contact",
            "/oob                          - Start the process to add a contact ( Out of the band Exchange )",
            "/add <oob_code>               - Add a contact with that <oob_code>",
            "/verify <code>                - Verifyy the contact <code>",
            "/delete <contact_id>          - DELETE selected contact, THIS PROCESS CANNOT BE UNDONE",
            "/setpassword                  - Set the main password for the Application",
            "/changepassword               - Change the current password for the Application",
            "/lock                         - Lock the current windows and ask for password",
            "/reset                        - Reset the Network Layer example (Rotate TOR Circuits)",
            "/clear                        - Clear the main window",
            "/status                       - Show Application status",
            "/search <keyword>             - Search for keywork on available messages",
            "/nick <contact_id> <nickname> - change nick of the given contact",
            "/exit or /quit                - close application",
            "/config                       - show current configuration",
            "/set <key> <value>            - set a new configuration key = value like tor_password"
        ]
        for line in lines:
            self.add_message(line)

    def shutdown(self):
        self.running = False
        curses.endwin()
        

    def function_config(self):
        for key, value in self.main_app.config.items():
            self.add_message("{} - {}".format(key,value))
            