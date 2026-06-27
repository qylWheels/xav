#include <wx/image.h>
#include <wx/wx.h>

#include "block_window.h"
#include "xavgui.h"
#include "xavlib/execution_monitor.h"

class XavApp : public wxApp {
public:
    bool OnInit() override;

private:
};

#define ICON_WIDTH 18
#define ICON_HEIGHT 18
#define SHEILD_GREEN_ICON "./xavgui/icons/shield_green.png"
#define UPDATE_ICON "./xavgui/icons/update.png"
#define SCAN_ICON "./xavgui/icons/scan.png"
#define SETTINGS_ICON "./xavgui/icons/settings.png"

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
    shield_icon.Rescale(64, 64, wxIMAGE_QUALITY_HIGH);
    if (shield_icon.IsOk()) {
        wxBitmap shield_icon_bitmap(shield_icon);
        auto win = wxFindWindowByName("security_status");
        auto icon = wxDynamicCast(win, wxStaticBitmap);
        icon->SetBitmap(shield_icon_bitmap);
    }

    // Set update icon
    wxImage update_icon(UPDATE_ICON, wxBITMAP_TYPE_PNG);
    update_icon.Rescale(ICON_WIDTH, ICON_HEIGHT, wxIMAGE_QUALITY_HIGH);
    if (update_icon.IsOk()) {
        wxBitmap update_icon_bitmap(update_icon);
        auto win = wxFindWindowByName("update_btn");
        auto update_btn = wxDynamicCast(win, wxButton);
        update_btn->SetBitmap(update_icon_bitmap);
    }

    // Set scan icon
    wxImage scan_icon(SCAN_ICON, wxBITMAP_TYPE_PNG);
    scan_icon.Rescale(ICON_WIDTH, ICON_HEIGHT, wxIMAGE_QUALITY_HIGH);
    if (scan_icon.IsOk()) {
        wxBitmap scan_icon_bitmap(scan_icon);
        auto win = wxFindWindowByName("scan_btn");
        auto scan_btn = wxDynamicCast(win, wxButton);
        scan_btn->SetBitmap(scan_icon_bitmap);
    }

    // Set settings icon
    wxImage settings_icon(SETTINGS_ICON, wxBITMAP_TYPE_PNG);
    settings_icon.Rescale(ICON_WIDTH, ICON_HEIGHT, wxIMAGE_QUALITY_HIGH);
    if (settings_icon.IsOk()) {
        wxBitmap settings_icon_bitmap(settings_icon);
        auto win = wxFindWindowByName("settings_btn");
        auto settings_btn = wxDynamicCast(win, wxButton);
        settings_btn->SetBitmap(settings_icon_bitmap);
    }

    mainwindow->Show();

    return true;
}
