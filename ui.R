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
    
    #DataTables_Table_0_length, #DataTables_Table_0_filter, #DataTables_Table_0_info, #DataTables_Table_0_paginate {
      font-size: 18px;
      color: #7ED3D6;
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
    
    .chart-pie:hover {
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
      border: 1px solid #4ECDC4;
      border-radius: 10px;
      padding: 15px;
    }
    
    .graph-container:last-child {
      margin-top: 15px;
    }
    
    .selectize-control.multi .selectize-input>div {
      background: #F82B26;
      color: #0E1F27;
      font-weight: 700
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
      leafletOutput("map"),
      
      div(class="table-container", DTOutput("ip_table")),
      
      div(class = "pie-charts-container",
          div(class='chart-pie', plotlyOutput("pie_chart_protocols")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_src_ip")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_dst_ip")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_src_port")),
          
          div(class='chart-pie', plotlyOutput("pie_chart_top_dst_port"))),
      
      div( class="graph-container", plotlyOutput("traffic_plot", height="600px")),
      
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
      )
    )
  )
)