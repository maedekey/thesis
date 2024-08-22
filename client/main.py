import clientinterface
import iofile
from user import User
import os


def main():
    """
    Main function. Asks the user the actions he wants to perform: create an account or log in. Then, retrieves invitations
    he sent and that have been sent to him. Finally, loads contact list, and allows him to send a request.
    :return:
    """
    init()
    inp = input("Enter the action you want to do: (l for login, c for create account, exit for exit)")
    username = input("Enter your username: ")
    user = None
    while inp != "exit":
        if inp == "l":
            user = User(username)
            user.loadUser()
        elif inp == "c":
            user = User(username)
            user.createUser()

        user.checkRequests()
        user.getRequests()
        user.getMessages(user.conn, user.username)
        contacts = clientinterface.getContacts(user.conn, user.username)
        inp = input("Please specify the action you want to do: (s for send a message, exit for exit)")
        if inp == "s":
            inp = sendRequest(contacts, user)


def init():
    """
    Function that create the /saved directory if not created yet
    :return:
    """
    dir_path = "saved"
    if not os.path.exists(dir_path):
        os.makedirs(dir_path)


def sendRequest(contacts, user):
    """
    Function that allows a user to send a request. If a request has never been sent between the selected user, creates
    message keys. Otherwise, loads preexisting ratchets.
    :param contacts: contact list. We have to check if the selected user is in it.
    :param user: the user we want to contact
    :return: input. Will loop until inp = exit
    """
    inp = input("Please specify the user you want to send a request to: ")
    if inp in contacts:
        user.loadRatchets(inp)
        message = ""
        ctr = iofile.getMessageCounter(user.username, inp)

        while message != "exit":
            message = sendMessages(ctr, inp, user)
    else:
        user.createSenderMessageKeys(inp)
        user.createRequest(inp)
    return inp


def sendMessages(ctr, inp, user):
    """
    Function that allows to send a message to another user.
    :param ctr: message counter. needed in case of desynchronisation.
    :param inp: selected user we want to send a message to
    :param user: user using the app
    :return:
    """
    message = input("Please specify the message you want to send: ")
    if message != "exit":
        clientinterface.sendMessage(user.conn, user.ratchets, user.username, message, inp, ctr)

        ctr += 1
        iofile.saveMessageCounter(user.username, ctr, inp)
    return message


main()
