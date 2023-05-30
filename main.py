"""Real time messenger with E.

Messenger using sockets which are live way of comunicating
rather than refreshing the page or saving stuff in the data base to
transmit the messages.
"""
from secrets import token_urlsafe
from flask import Flask, render_template, request, session, redirect, url_for
from flask_socketio import join_room, leave_room, send, SocketIO
# from ElGamal import ELGamal

app = Flask(__name__)
app.config["SECRET_KEY"] = "ZVNWwozcg34rxEpDgPGg1IXf8mPxiUkKo9q6osBywXIEKTU1l7MuRSSzF72IgUmDXckeds"
socketio = SocketIO(app)

rooms = {}

def generate_unique_code(length: int):
    """
    Generating unique codes.
    """
    if not isinstance(length, int):
        raise TypeError('invalid type, int expected')

    while True:
        code = token_urlsafe(8)

        if code not in rooms:
            break

    return code


@app.route("/", methods=["POST", "GET"])
@app.route('/home', methods=["POST", "GET"])
def home():
    """
    Home page.
    """
    session.clear()
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join", False)
        create = request.form.get("create", False)

        if not name:
            return render_template(
                "home.html", error = "Please enter a nickname.", code = code, name = name
            )

        if join is not False and not code:
            return render_template(
                "home.html", error = "Please enter a room code.", code = code, name = name
            )

        room = code
        if create is not False:
            room = generate_unique_code(10)
            rooms[room] = {"members": 0, "messages": [], "users": {}}
        elif code not in rooms:
            return render_template(
                "home.html", error = "Room does not exist.", code = code, name = name
            )

        session["room"] = room
        session["name"] = name
        return redirect(url_for("room"))

    return render_template("home.html")


@app.route("/room")
def room():
    """
    Chat room page.
    """
    room = session.get("room")
    if room is None or session.get("name") is None or room not in rooms:
        return redirect(url_for("home"))

    return render_template("room.html", code = room, messages = rooms[room]["messages"])


@socketio.on("message")
def message(data):
    """
    Message.
    """
    room = session.get("room")
    if room not in rooms:
        return

    content = {"name": session.get("name"), "message": data["data"]}
    send(content, to = room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {data['data']}")


@socketio.on("connect")
def connect():
    """
    Initializing the socket.
    """
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return

    join_room(room)
    send({"name": name, "message": "has entered the room"}, to = room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")


@socketio.on("disconnect")
def disconnect():
    """
    Disconnect.
    """
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]

    send({"name": name, "message": "has left the room"}, to = room)
    print(f"{name} has left the room {room}")


if __name__ == "__main__":
    socketio.run(app, debug = True)
