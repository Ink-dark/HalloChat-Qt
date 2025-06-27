import QtQuick 6.2
import QtQuick.Controls 6.2
import QtQuick.Layouts 6.2
import Qt.labs.settings 1.0

Window {
    id: mainWindow
    width: 800
    height: 600
    title: qsTr("HalloChat")
    visible: true

    Settings {
        id: appSettings
        property alias windowWidth: mainWindow.width
        property alias windowHeight: mainWindow.height
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 10
        padding: 10

        Text {
            text: qsTr("实时聊天应用")
            font.pointSize: 20
            Layout.alignment: Qt.AlignHCenter
        }

        ListView {
            id: messageView
            Layout.fillWidth: true
            Layout.fillHeight: true
            model: ListModel { id: messageModel }
            delegate: ItemDelegate {
                width: parent.width
                Text {
                    text: model.message
                    color: model.isOwnMessage ? "#2196F3" : "#333333"
                    horizontalAlignment: model.isOwnMessage ? Text.AlignRight : Text.AlignLeft
                    padding: 8
                    background: Rectangle {
                        color: model.isOwnMessage ? "#E3F2FD" : "#F5F5F5"
                        radius: 8
                    }
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 5

            TextField {
                id: messageInput
                Layout.fillWidth: true
                placeholderText: qsTr("输入消息...")
                onAccepted: sendMessage()
            }

            Button {
                text: qsTr("发送")
                onClicked: sendMessage()
            }
        }
    }

    function sendMessage() {
        if (messageInput.text.trim() !== "") {
            // 调用C++后端发送消息
            databaseManager.sendMessage(messageInput.text)
            // 添加到本地消息列表
            messageModel.append({
                message: messageInput.text,
                isOwnMessage: true
            })
            messageInput.text = ""
            messageView.positionViewAtEnd()
        }
    }

    // 连接服务器信号
    Connections {
        target: server
        function onNewMessageReceived(message, sender) {
            messageModel.append({
                message: sender + ": " + message,
                isOwnMessage: false
            })
            // 滚动到底部
            messageView.positionViewAtEnd()
        }
    }

    Component.onCompleted: {
        // 加载历史消息
        const history = databaseManager.getChatHistory()
        for (let i = 0; i < history.length; i++) {
            messageModel.append(history[i])
        }
        messageView.positionViewAtEnd()
    }
}