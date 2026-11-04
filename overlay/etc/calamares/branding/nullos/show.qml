import QtQuick 2.0;
import calamares.slideshow 1.0;

Presentation {
    id: presentation

    Timer {
        interval: 9000
        running: true
        repeat: true
        onTriggered: presentation.goToNextSlide()
    }

    Slide {
        Rectangle { anchors.fill: parent; color: "#0b0b0d" }
        Text { anchors.centerIn: parent; width: parent.width * 0.8; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
               color: "#c8c8c8"; font.pixelSize: 22
               text: "NullOS is installing.\n\nYour system is being copied from the live image. Nothing is downloaded." }
    }
    Slide {
        Rectangle { anchors.fill: parent; color: "#0b0b0d" }
        Text { anchors.centerIn: parent; width: parent.width * 0.8; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
               color: "#c8c8c8"; font.pixelSize: 22
               text: "Security Center (Super+S)\n\nRestricted Mode, kill switch, audits, sandboxes and labs.\nEvery status is verified against the real system." }
    }
    Slide {
        Rectangle { anchors.fill: parent; color: "#0b0b0d" }
        Text { anchors.centerIn: parent; width: parent.width * 0.8; horizontalAlignment: Text.AlignHCenter; wrapMode: Text.WordWrap
               color: "#c8c8c8"; font.pixelSize: 22
               text: "After the restart\n\nLog in with the account you created.\nOpen the start menu with Super+Space." }
    }
}
