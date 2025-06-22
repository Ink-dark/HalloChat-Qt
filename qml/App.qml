import QtQuick 6.2
import QtQuick.Controls 6.2
import QtQuick.Layouts 6.2

Window {
    width: 800
    height: 600
    title: qsTr("HalloChat")
    visible: true

    ColumnLayout {
        anchors.fill: parent
        padding: 10
        spacing: 10

        Text {
            text: qsTr("实时聊天应用")
            font.pointSize: 20
            Layout.alignment: Qt.AlignHCenter
        }

        TextArea {
            id: chatHistory
            readOnly: true
            Layout.fillWidth: true
            Layout.fillHeight: true
            placeholderText: qsTr("聊天记录...")
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 5

            TextField {
                id: messageInput
                placeholderText: qsTr("输入消息...")
                Layout.fillWidth: true
                onAccepted: {
                    if (text.trim() !== "") {
                        dbManager.sendMessage(text)
                        text = ""
                    }
                }
            }

            Button {
                text: qsTr("发送")
                onClicked: {
                    if (messageInput.text.trim() !== "") {
                        dbManager.sendMessage(messageInput.text)
                        messageInput.text = ""
                    }
                }
            }
        }
    }
}