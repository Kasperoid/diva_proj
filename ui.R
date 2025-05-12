library(shiny)
library(leaflet)
library(DT)

ui <- fluidPage(
  tags$style(HTML("
    body {
      background-color: #f7f7f7;
    }
    
    .container {
      background-color: #ffffff;
      margin: 15px 0;
      width: 100%;
      border-radius: 10px;
      box-shadow: 0px 0px 14px 0px rgba(34, 60, 80, 0.2);
      padding: 12px;
    }
    
    .logo {
      margin: 0;
      text-align: center;
      font-weight: bold;
    }
    
    .horizontal-line {
      width: 90%;
      height: 2px;
      background-color: #f0f0f0;
      margin: 5px auto;
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
      border: 1px solid #dbdbdb;
      border-radius: 10px;
      padding: 15px;
    }
    
    .chart-pie:hover {
      box-shadow: 0px 0px 14px 0px rgba(34, 60, 80, 0.2);
      transition: 0.3s ease-in-out;
    }
    
    .graph-container {
      border: 1px solid #dbdbdb;
      border-radius: 10px;
      padding: 15px;
    }
                  "
  )),
  
  div(
    class="container",
    h1(class='logo', 'DIVA'),
    
    div(class="horizontal-line"),
    
    div(
      class="options-container",
      fileInput('fileData', 'Загрузите csv/log файл',
                multiple = FALSE,
                accept = c("text/csv", ".csv", ".log")),
      
      div(
        class="downloand-container",
        downloadButton("download_html", "Скачать HTML"),
      )
    ),
    
    leafletOutput("map"),
    
    div(class="table-container", DTOutput("ip_table")),
    
    div(class = "pie-charts-container",
        div(class='chart-pie', plotlyOutput("pie_chart_protocols")),
        
        div(class='chart-pie', plotlyOutput("pie_chart_top_src_ip")),
        
        div(class='chart-pie', plotlyOutput("pie_chart_top_dst_ip")),
        
        div(class='chart-pie', plotlyOutput("pie_chart_top_src_port")),
        
        div(class='chart-pie', plotlyOutput("pie_chart_top_dst_port"))),
    
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