library(shiny)
library(leaflet)
library(DT)
library(plotly)
library(shinybusy)

ui <- fluidPage(
  tags$style(HTML("
    body {
      font-family: 'Consolas';
      background-color: #12303B;
    }
    
    .container {
      background-color: #0E1F27;
      margin: 15px 0;
      width: 100%;
      border-radius: 10px;
      box-shadow: 0px 0px 14px 9px rgba(126, 211, 214, 0.28);
      padding: 12px;
    }
    
    .logo {
      font-family: 'Courier New';
      font-size: 64px;
      margin: 0;
      text-align: center;
      font-weight: bold;
      color: #7ED3D6;
    }
    
    .horizontal-line {
      width: 90%;
      height: 2px;
      background-color: #12303B;
      margin: 5px auto;
    }
    
    #fileData-label {
      font-size: 18px;
      font-weight: 700;
      color: #7ED3D6;
    }
    
    .map_info_container {
      display: flex;
      gap: 10px;
      align-items: center;
      margin-bottom: 15px;
    }
    
    .cards-ip-container {
      display: flex;
      justify-content: center;
      gap: 15px;
      margin-top: 15px;
    }
    
    .map_container {
      flex: 1;
    }
    
    .table_cointainer {
      flex: 0.3;
    }
    
    .input-group-btn:first-child>.btn, .input-group .form-control:last-child  {
      font-size: 18px;
      height: auto;
    }
    
    .btn-default {
      font-size: 18px;
    }
    
    .btn-default:hover {
      background-color: #7ED3D6;
      border-color: #0E1F27;
      transition: 0.5s ease-in-out;
      font-weight: 800;
    }
    
    .btn-default:focus {
      background-color: #4A7B7D;
      color: white;
    }
    
    .options-container {
      display: flex;
      justify-content: space-between;
    }
    
    .downloand-container {
      display: flex;
      flex-direction: column;
      gap: 5px;
    }
      
    .table-container {
      margin-top: 30px;
    }
    
    .dataTables_length, .dataTables_filter, .dataTables_info, .dataTables_paginate {
      font-size: 18px;
      color: #7ED3D6 !important;
    }
    
    .dataTables_wrapper .dataTables_paginate .paginate_button:hover, .dataTables_wrapper .dataTables_paginate .paginate_button.current, .dataTables_wrapper .dataTables_paginate .paginate_button.current:hover {
      border: 1px solid #7ED3D6;
      background: #7ED3D6;
      color: white !important;
      transition: 0.3s ease;
    }
    
    .dataTables_wrapper .dataTables_paginate .paginate_button.current {
      border: 1px solid #F82B26;
      background: #F82B26;
      color: #0E1F27 !important;
    }
    
    #DataTables_Table_0_length option {
      background-color: #0E1F27;
    }
    
    .card-info-container {
      text-align: center;
      padding: 10px;
      border: 1px solid #F82B26;
      min-width: 300px;
      border-radius: 10px;
    }
    
    #label_uniq_src,  #label_uniq_dst, #label_count_syn, #label_count_ack, #label_src_traffic, #label_dst_traffic, #label_top_dst_ip, #anomaly_status{
      font-size: 22px;
      color: #7ED3D6;
    }
    
    #text_uniq_src, #text_uniq_dst, #text_count_syn, #text_count_ack, #text_src_traffic, #text_dst_traffic {
      font-size: 64px;
      font-weight: 800;
      color: #F82B26;
    }
    
    #text_top_dst_ip {
      font-size: 32px;
      font-weight: 800;
      color: #F82B26;
    }
    
    .pie-charts-container {
      display: flex;
      flex-wrap: wrap;
      margin: 15px 0;
      gap: 10px;
      justify-content: center;
    }
    
    .chart-pie {
      flex: 50%;
      max-width: 45%;
      padding: 10px;
      border-radius: 10px;
      border: 1px solid #4ECDC4;
    }
    
    .chart-pie:hover, .card-info-container:hover {
      box-shadow: 0px 0px 17px 8px rgba(78, 205, 196, 0.25);
      transition: 0.3s ease-in-out;
    }
    
    .well, .selectize-input {
      background-color: transparent !important;
      border-color: #7ED3D6;
      color: #7ED3D6;
      font-size: 18px;
    }
    
    .radio input[type=radio] {
      accent-color: #F82B26;
    }
    
    .selectize-dropdown-content {
      background: #0E1F27 !important;
      color: #7ED3D6;
    }
    
    .graph-container {
      flex: 1;
      border: 1px solid #4ECDC4;
      border-radius: 10px;
      padding: 15px;
    }
    
    .graph-info-container {
      display: flex;
      gap: 10px;
      align-items: center;
    }
    
    .traffic-value-container {
      margin-bottom: 10px;
    }
    
    .graph-container:last-child {
      margin-top: 15px;
    }
    
    .selectize-control.multi .selectize-input>div {
      background: #F82B26;
      color: #0E1F27;
      font-weight: 700
    }
    
    .traffic-cards-container {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    
    .anomaly-info-container {
      display: flex;
      gap: 10px;
      align-items: center;
      margin-bottom: 10px;
    }
    
    .anomaly-control-container {
      background-color: inherit !important;
      border: 1px solid #4ECDC4;
      border-radius: 10px !important;
    }
    
    .anomaly-control-container .control-label, .anomaly-control-container .irs-min, .anomaly-control-container .irs-max {
      font-size: 18px;
      color: #4ECDC4;
    }
    
    .anomaly-control-container .irs-grid-text {
      font-size: 12px;
      color: #4ECDC4;
    }
    
    .btn-anomaly-reload {
      background-color: #4ECDC4;
      border-color: #4ECDC4;
    }
    
    .irs--shiny .irs-bar {
      border-top: 1px solid #F82B26;
      border-bottom: 1px solid #F82B26;
      background: #F82B26;
    }
    
    .irs-single {
      background-color: #F82B26 !important;
    }
  "
  )),
  
  add_busy_gif(
    src = "logo-loader.gif",
    timeout = 500,
    position = "full-page",
    height = 300, width = 300,
    overlay_color = "#12303B"
  ),
  
  div(
    class="container",
    h1(class='logo', 'D.I.V.A'),
    
    div(class="horizontal-line"),
    
    div(
      class="options-container",
      fileInput('fileData', 'Загрузите csv/log файл',
                multiple = FALSE,
                accept = c("text/csv", ".csv", ".log"),
                buttonLabel = "Найти",
                placeholder = "Файл не выбран..."
                ),
      
      conditionalPanel(
        condition = "output.file_loaded",
        div(
          class="downloand-container",
          downloadButton("download_html", "Скачать HTML"),
        )
      )
    ),
    
    conditionalPanel(
      condition = "output.file_loaded",
      div(class="map_info_container",
        div(class="map_container", leafletOutput("map")),
        div(class="info_container", DTOutput("top_map_points")), 
      ),
      
      div(class="table_container", DTOutput("ip_table")),
      
      div(class="cards-ip-container", 
          div(class="card-info-container", textOutput("label_uniq_src"), textOutput("text_uniq_src")),
          
          div(class="card-info-container", textOutput("label_uniq_dst"), textOutput("text_uniq_dst")),
          
          div(class="card-info-container", textOutput("label_count_syn"), textOutput("text_count_syn")),
          
          div(class="card-info-container", textOutput("label_count_ack"), textOutput("text_count_ack"))),
      
      div(class = "pie-charts-container",
          div(class='chart-pie', plotlyOutput("pie_chart_protocols")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_src_ip")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_dst_ip")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_src_port")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_dst_port"))),
      
      div(class="anomaly-info-container",
        div(
          class = "graph-container",
          plotlyOutput("anomaly_plot")
        ),
        div(
          div(
            class = "anomaly-control-container",
            style = "margin: 15px 0; padding: 15px; background: #f8f9fa; border-radius: 8px;",
            sliderInput("anomaly_threshold", "Порог аномалии:",
                        min = 0.1, max = 1.0, value = 0.6, step = 0.05),
            actionButton("retrain_btn", "Переобучить модель", 
                         icon = icon("sync-alt"),
                         class = "btn-anomaly-reload")
          ) 
        )
      ),
      
      div(class="traffic-value-container graph-info-container",
        div( class="graph-container", plotlyOutput("traffic_plot", height="600px")),
        
        div(class="traffic-cards-container",
          div(class="card-info-container", textOutput("label_src_traffic"), textOutput("text_src_traffic")),
          
          div(class="card-info-container", textOutput("label_dst_traffic"), textOutput("text_dst_traffic"))
        ),
      ),
      
      div(class='graph-info-container',
          div( class="graph-container",
               sidebarLayout(
                 sidebarPanel(
                   radioButtons("ipType", "Тип IP-адреса:",
                                choices = c("Источник (src)" = "src",
                                            "Получатель (dst)" = "dst"),
                                selected = "src"),
                   selectInput("selectedIP", "Выберите IP-адрес:",
                               choices = NULL),
                   selectInput("timeGrouping", "Группировка времени:",
                               choices = c("По секундам" = "sec",
                                           "По минутам" = "min",
                                           "По часам" = "hour"))
                 ),
                 mainPanel(
                   plotlyOutput("ipActivityPlot", height = "800px")
                 )
               )
          ),
          
          div(class="card-info-container", textOutput("label_top_dst_ip"), textOutput("text_top_dst_ip")),
      ),
      
      div(class="graph-info-container",
          div(class="graph-container", 
              sidebarLayout(
                sidebarPanel(
                  width = 3,
                  selectInput("date_select", "Выберите дату:", choices = NULL),
                  selectInput("ip_select", "Выберите IP назначения:", 
                              choices = NULL, multiple = TRUE),
                  selectInput("port_select", "Выберите порт назначения:", 
                              choices = NULL, multiple = TRUE),
                  radioButtons("time_group", "Группировка по времени:",
                               choices = c("Часы" = "hour", 
                                           "Минуты" = "minute", 
                                           "Секунды" = "second"),
                               selected = "minute")
                ),
                mainPanel(
                  width = 9,
                  plotlyOutput("syn_ack_plot", height = "600px")
                )
              )
          ),
          div(class="card-info-container", textOutput("anomaly_status"))
      )
    )
  )
)