#include <wx/image.h>
#include <wx/wx.h>

#include "block_window.h"
#include "xavgui.h"
#include "xavlib/execution_monitor.h"

class XavApp : public wxApp {
public:
    bool OnInit() override;
    void open_scan_window(wxCommandEvent& event);

private:
};

#define BIG_ICON_WIDTH 64
#define BIG_ICON_HEIGHT 64
#define BUTTON_ICON_WIDTH 18
#define BUTTON_ICON_HEIGHT 18

#define SHEILD_GREEN_ICON "./xavgui/icons/shield_green.png"
#define UPDATE_ICON "./xavgui/icons/update.png"
#define SCAN_ICON "./xavgui/icons/scan.png"
#define SETTINGS_ICON "./xavgui/icons/settings.png"
#define START_ICON "./xavgui/icons/start.png"
#define CANCEL_ICON "./xavgui/icons/cancel.png"
#define PAUSE_ICON "./xavgui/icons/pause.png"

wxIMPLEMENT_APP(XavApp);

bool XavApp::OnInit() {
    wxInitAllImageHandlers();

    auto mainwindow = new MainWindow(nullptr);

    // Set window size
    auto screen_size = wxGetDisplaySize();
    auto width = screen_size.GetWidth() * 0.5;
    auto height = screen_size.GetHeight() * 0.5;
    mainwindow->SetSize(width, height);

    // Set shield icon
    wxImage shield_icon(SHEILD_GREEN_ICON, wxBITMAP_TYPE_PNG);
    shield_icon.Rescale(BIG_ICON_WIDTH, BIG_ICON_HEIGHT, wxIMAGE_QUALITY_HIGH);
    if (shield_icon.IsOk()) {
        wxBitmap shield_icon_bitmap(shield_icon);
        auto win = wxFindWindowByName("security_status");
        auto icon = wxDynamicCast(win, wxStaticBitmap);
        icon->SetBitmap(shield_icon_bitmap);
    }

    // Set update icon
    wxImage update_icon(UPDATE_ICON, wxBITMAP_TYPE_PNG);
    update_icon.Rescale(BUTTON_ICON_WIDTH, BUTTON_ICON_HEIGHT,
                        wxIMAGE_QUALITY_HIGH);
    if (update_icon.IsOk()) {
        wxBitmap update_icon_bitmap(update_icon);
        auto win = wxFindWindowByName("update_btn");
        auto update_btn = wxDynamicCast(win, wxButton);
        update_btn->SetBitmap(update_icon_bitmap);
    }

    // Set scan icon
    wxImage scan_icon(SCAN_ICON, wxBITMAP_TYPE_PNG);
    scan_icon.Rescale(BUTTON_ICON_WIDTH, BUTTON_ICON_HEIGHT,
                      wxIMAGE_QUALITY_HIGH);
    if (scan_icon.IsOk()) {
        wxBitmap scan_icon_bitmap(scan_icon);
        auto win = wxFindWindowByName("scan_btn");
        auto scan_btn = wxDynamicCast(win, wxButton);
        scan_btn->SetBitmap(scan_icon_bitmap);
    }

    // Set settings icon
    wxImage settings_icon(SETTINGS_ICON, wxBITMAP_TYPE_PNG);
    settings_icon.Rescale(BUTTON_ICON_WIDTH, BUTTON_ICON_HEIGHT,
                          wxIMAGE_QUALITY_HIGH);
    if (settings_icon.IsOk()) {
        wxBitmap settings_icon_bitmap(settings_icon);
        auto win = wxFindWindowByName("settings_btn");
        auto settings_btn = wxDynamicCast(win, wxButton);
        settings_btn->SetBitmap(settings_icon_bitmap);
    }

    // Set scan button click handler
    auto win = wxFindWindowByName("scan_btn");
    auto scan_btn = wxDynamicCast(win, wxButton);
    scan_btn->Connect(wxEVT_BUTTON,
                      wxCommandEventHandler(XavApp::open_scan_window), nullptr,
                      mainwindow);

    mainwindow->Show();

    return true;
}

class ScanWindowDerived : public ScanWindow {
public:
    ScanWindowDerived(wxWindow* parent) : ScanWindow(parent) {
        // Set window size
        auto screen_size = wxGetDisplaySize();
        auto width = screen_size.GetWidth() * 0.5;
        auto height = screen_size.GetHeight() * 0.5;
        this->SetSize(width, height);

        // Set scan icon
        wxImage scan_icon(SCAN_ICON, wxBITMAP_TYPE_PNG);
        scan_icon.Rescale(BIG_ICON_WIDTH, BIG_ICON_HEIGHT,
                          wxIMAGE_QUALITY_HIGH);
        if (scan_icon.IsOk()) {
            wxBitmap scan_icon_bitmap(scan_icon);
            this->scan_icon->SetBitmap(scan_icon_bitmap);
        }

        // Set scan button icon
        wxImage scan_btn_icon(START_ICON, wxBITMAP_TYPE_PNG);
        scan_btn_icon.Rescale(BUTTON_ICON_WIDTH, BUTTON_ICON_HEIGHT,
                              wxIMAGE_QUALITY_HIGH);
        if (scan_btn_icon.IsOk()) {
            wxBitmap scan_btn_icon_bitmap(scan_btn_icon);
            this->start_scan_btn->SetBitmap(scan_btn_icon_bitmap);
        }

        // Set pause button icon
        wxImage pause_btn_icon(PAUSE_ICON, wxBITMAP_TYPE_PNG);
        pause_btn_icon.Rescale(BUTTON_ICON_WIDTH, BUTTON_ICON_HEIGHT,
                               wxIMAGE_QUALITY_HIGH);
        if (pause_btn_icon.IsOk()) {
            wxBitmap pause_btn_icon_bitmap(pause_btn_icon);
            this->pause_btn->SetBitmap(pause_btn_icon_bitmap);
        }

        // Set cancel button icon
        wxImage cancel_btn_icon(CANCEL_ICON, wxBITMAP_TYPE_PNG);
        cancel_btn_icon.Rescale(BUTTON_ICON_WIDTH, BUTTON_ICON_HEIGHT,
                                wxIMAGE_QUALITY_HIGH);
        if (cancel_btn_icon.IsOk()) {
            wxBitmap cancel_btn_icon_bitmap(cancel_btn_icon);
            this->cancel_btn->SetBitmap(cancel_btn_icon_bitmap);
        }

        // Set list header
        this->scan_result_list->InsertColumn(0, wxT("Path"), wxLIST_FORMAT_LEFT,
                                             screen_size.GetWidth() * 0.3);
        this->scan_result_list->InsertColumn(1, wxT("Threat Name"),
                                             wxLIST_FORMAT_LEFT,
                                             wxLIST_AUTOSIZE_USEHEADER);
    }
};

void XavApp::open_scan_window(wxCommandEvent& event) {
    auto scan_window = new ScanWindowDerived(nullptr);
    scan_window->Show();
}
