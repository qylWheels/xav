#include "block_window.h"

namespace xav {
BlockWindow::BlockWindow()
    : wxFrame(nullptr, wxID_ANY, wxT("Xav Security Warning"), wxDefaultPosition,
              wxDefaultSize,
              wxDEFAULT_FRAME_STYLE & ~(wxRESIZE_BORDER | wxMAXIMIZE_BOX)) {
    // Panel
    auto panel = new wxPanel(this);

    // Layout
    auto vbox = new wxBoxSizer(wxVERTICAL);
    auto alert_icon_and_detail_box = new wxBoxSizer(wxHORIZONTAL);
    auto alert_icon_box = new wxBoxSizer(wxVERTICAL);
    auto detail_box = new wxBoxSizer(wxVERTICAL);
    auto button_box = new wxBoxSizer(wxHORIZONTAL);
    vbox->Add(alert_icon_and_detail_box, 4, wxEXPAND, 0);
    vbox->Add(button_box, 1, wxEXPAND, 0);
    alert_icon_and_detail_box->Add(alert_icon_box, 1, wxEXPAND, 0);
    alert_icon_and_detail_box->Add(detail_box, 3, wxEXPAND, 0);
    panel->SetSizer(vbox);

    // Content
    wxImage image("../../../../xavgui/icons/shield.png", wxBITMAP_TYPE_PNG);
    image.Rescale(48, 48, wxIMAGE_QUALITY_HIGH);
    if (image.IsOk()) {
        wxBitmap bitmap(image);
        auto icon = new wxStaticBitmap(panel, wxID_ANY, bitmap);
        alert_icon_box->Add(icon, 0, wxALIGN_CENTER_HORIZONTAL | wxTOP, 75);
    }

    auto alert_title = new wxStaticText(panel, wxID_ANY, wxT("THREAT BLOCKED"));
    alert_title->SetFont(
        wxFont(16, wxFONTFAMILY_SWISS, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_BOLD));
    alert_title->SetForegroundColour(wxColour(214, 48, 49));
    detail_box->Add(alert_title,
                    wxSizerFlags().Proportion(0).Border(wxTOP, 35));

    auto notice = new wxStaticText(
        panel, wxID_ANY,
        wxT("Xav has just blocked a threat, your system is safe."));
    notice->SetForegroundColour(wxColour(45, 52, 54));
    detail_box->Add(notice, wxSizerFlags().Proportion(0));

    auto path = new wxStaticText(panel, wxID_ANY,
                                 wxT("path: /home/comma/sample/silverfox.exe"));
    path->SetForegroundColour(wxColour(45, 52, 54));
    detail_box->Add(path, wxSizerFlags().Proportion(0).Border(wxTOP, 25));

    auto type =
        new wxStaticText(panel, wxID_ANY, wxT("type: Generic.8cs787cioix"));
    type->SetForegroundColour(wxColour(45, 52, 54));
    detail_box->Add(type, wxSizerFlags().Proportion(0).Border(wxTOP, 5));

    auto quarantine = new wxButton(panel, wxID_ANY, wxT("Quarantine"));
    auto cancel = new wxButton(panel, wxID_ANY, wxT("Cancel"));
    button_box->Add(quarantine,
                    wxSizerFlags().Proportion(1).Border(wxLEFT | wxRIGHT, 50));
    button_box->Add(cancel,
                    wxSizerFlags().Proportion(1).Border(wxLEFT | wxRIGHT, 50));
}
}  // namespace xav
