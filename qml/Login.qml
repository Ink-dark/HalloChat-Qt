import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

ColumnLayout {
    id: loginForm
    width: 300
    height: 200
    spacing: 15
    anchors.centerIn: parent

    TextField {
        id: username
        placeholderText: "用户名"
        Layout.fillWidth: true
        validator: RegExpValidator { regExp: /^[a-zA-Z0-9_]{3,20}$/ }
        ToolTip.text: "用户名必须为3-20位字母、数字或下划线"
        ToolTip.visible: hovered && text.length > 0 && !validator.validate(text, 0)
    }

    TextField {
        id: password
        placeholderText: "密码"
        echoMode: TextInput.Password
        Layout.fillWidth: true
        validator: RegExpValidator { regExp: /^.{6,}$/ }
        ToolTip.text: "密码至少6位"
        ToolTip.visible: hovered && text.length > 0 && !validator.validate(text, 0)
    }

    Button {
        text: "登录"
        Layout.fillWidth: true
        onClicked: {
            if (!username.validator.validate(username.text, 0)) {
                errorLabel.text = "用户名格式不正确";
                return;
            }
            if (!password.validator.validate(password.text, 0)) {
                errorLabel.text = "密码长度不能少于6位";
                return;
            }
            authManager.login(username.text, password.text);
        }
    }

    Text {
        id: errorLabel
        color: "red"
        font.pixelSize: 12
        visible: text.length > 0
        Layout.fillWidth: true
        horizontalAlignment: Text.AlignHCenter
    }

    Connections {
        target: authManager
        function onLoginSuccess(token) {
            // 登录成功处理，如导航到主界面
            console.log("登录成功，令牌: " + token)
        }
        function onLoginFailed(message) {
            errorLabel.text = message
        }
    }
}