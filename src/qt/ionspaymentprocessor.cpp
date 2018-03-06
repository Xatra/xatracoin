#include "ionspaymentprocessor.h"
#include <QString>
#include <iostream>

IONSPaymentProcessor::IONSPaymentProcessor(BitcoinGUI * gui, QObject * parent)
    : QObject(parent), gui(gui)
{
}

void IONSPaymentProcessor::pay(QString address, QString fee)
{
    QString uri("Xatracoin:" + address + "?amount=" + fee);
    gui->handleURI(uri);
}
