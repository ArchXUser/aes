#include "mainwindow.hpp"
#include "ui_mainwindow.h"
#include "aes256.hpp"

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->convertButton->setDisabled(true);

    ui->encodeRadioButton->setChecked(true);
    encryption_mode = EncryptionMode::Encode;
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::generateButton()
{
    QString textkey;

    for (unsigned int i = 0; i < 32; i++)
    {
        QChar symbol = QChar(rand() % 57 + 48);

        textkey.append(symbol);
        key[i] = symbol.unicode();
    }
    ui->keyLineEdit->setText(textkey);

    if (not ui->input->toPlainText().isEmpty()) {
        ui->convertButton->setDisabled(false);
    }
}

void MainWindow::convertButton()
{
    QString intext = ui->input->toPlainText();
    QString outtext;
    AES256 aes;

    switch (encryption_mode) {
        case EncryptionMode::Encode:
            outtext = QString::fromStdString(aes.encrypt(intext.toStdString(), key));
            break;
        case EncryptionMode::Decode:
            outtext = QString::fromStdString(aes.decrypt(intext.toStdString(), key));
            break;
    }
    ui->output->setPlainText(outtext);
}

void MainWindow::setEncodeMode()
{
    encryption_mode = EncryptionMode::Encode;
}

void MainWindow::setDecodeMode()
{
    encryption_mode = EncryptionMode::Decode;
}

void MainWindow::toggleConvertButton()
{
    if (ui->input->toPlainText().isEmpty()) {
        ui->convertButton->setDisabled(true);
    }
    else if (not ui->keyLineEdit->text().isEmpty()) {
        ui->convertButton->setDisabled(false);
    }
}
