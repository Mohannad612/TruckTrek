socket_tokens = {}


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.String(500), nullable=False)
    reply_to_id = db.Column(db.Integer, db.ForeignKey('message.id'), nullable=True)
    read = db.Column(db.Boolean, default=False)
    read_timestamp = db.Column(db.DateTime, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())



@app.route('/chat')
@login_required
def chat():
    all_users = User.query.filter(User.id != current_user.id).all()
    users = {}

    for user in all_users:

        latest_message = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.recipient_id == user.id)) |
            ((Message.sender_id == user.id) & (Message.recipient_id == current_user.id))
        ).order_by(Message.timestamp.desc()).first()

        if latest_message:
            timestamp_utc = latest_message.timestamp.replace(tzinfo=timezone.utc).isoformat()
            users[user.id] = {
                'username': user.username,
                'latest_message': latest_message.content,
                'profile_pic': user.profile_pic,
                'name': user.first_name + ' ' + user.last_name,
                'me': latest_message.sender_id == current_user.id,
                'read': latest_message.read if latest_message.recipient_id == current_user.id else True,
                'orig_timestamp': timestamp_utc,
                'timestamp': latest_message.timestamp.strftime('%b %d, %Y %I:%M %p'),
                'message_id': latest_message.id
            }
        else:
            users[user.id] = {
                'username': user.username,
                'profile_pic': user.profile_pic,
                'name': user.first_name + ' ' + user.last_name,
                'latest_message': None,
                'read': True,
                'timestamp': None,
                'message_id': None
            }

    sorted_users = dict(sorted(users.items(), key=lambda item: item[1]['timestamp'] or '', reverse=True))
    return render_template('chat.html', username=current_user.username, users=sorted_users)
@app.route('/generate_socket_token')
@login_required
def generate_socket_token():
    token = secrets.token_urlsafe(16)
    socket_tokens[token] = current_user.id
    return jsonify({'socket_token': token})


@socketio.on('connect')
def handle_connect():
    token = request.args.get('token')
    user_id = socket_tokens.pop(token, None)

    if user_id is None:
        disconnect()
        return

    user = User.query.get(user_id)
    if user is None:
        disconnect()
        return

    join_room(user.unique_id)
    print(f'User {user.username} connected with token {token}')

@socketio.on('disconnect')
def handle_disconnect():
    user = current_user
    if user:
        leave_room(user.unique_id)
        print(f'User {user.username} disconnected')

@socketio.on('message')
def handle_message(data):
    sender = User.query.filter_by(username=data['username']).first()
    recipient = User.query.filter_by(username=data['recipient']).first()
    reply_to_id = data.get('reply_to_id')

    new_message = Message(sender_id=sender.id, recipient_id=recipient.id, content=data['message'], reply_to_id=reply_to_id)
    db.session.add(new_message)
    db.session.commit()
    timestamp_utc = new_message.timestamp.replace(tzinfo=timezone.utc).isoformat()

    message_data = {
        'username': data['username'],
        'name': sender.first_name + ' ' + sender.last_name,
        'profile_pic': sender.profile_pic,
        'message': data['message'],
        'recipient': data['recipient'],
        'reply_to_id': reply_to_id,
        'message_id': new_message.id,
        'timestamp': timestamp_utc
    }

    emit('message', message_data, room=recipient.unique_id)
    emit('message', message_data, room=sender.unique_id)

if __name__ == "__main__":
    socketio.run(app, debug=True, host='0.0.0.0', port=5500)

