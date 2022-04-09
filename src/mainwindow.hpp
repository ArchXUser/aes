#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

enum class EncryptionMode { Encode, Decode };

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

public slots:
    void generateButton();
    void convertButton();
    void setEncodeMode();
    void setDecodeMode();
    void toggleConvertButton();

private:
    Ui::MainWindow *ui;
    EncryptionMode encryption_mode;
    uint8_t key[32];
};
#endif // MAINWINDOW_H
