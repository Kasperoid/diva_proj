library(shiny)
library(stringr)
library(dplyr)
library(tidyr)
library(lubridate)
library(sys)
library(httr)
source("config.R")
library(countrycode)
library(readr)
library(DT)
library(rmarkdown)
library(ggplot2)
library(plotly)
library(shinybusy)
library(vroom)
library(isotree) 

api_url <- 'https://www.virustotal.com/api/v3/ip_addresses/'

server <- function(input, output, session) {
  
  # Получение рейтинга и страны через запрос на API virusTotal (v3)
  check_ip_virustotal <- function(ip, saved_ips_df) { # ip - айпи, saved_ips_df - таблица с сохраненными айпишниками
    reqUrl <- sprintf("%s%s", api_url, ip)
    response <- GET(url=reqUrl, add_headers(.headers=c('X-Apikey' = api_key)))
    
    Sys.sleep(5) # Установка задержки между запросами
    
    if (status_code(response) == 200) { # При успешном результате обработка
      content_data <- content(response, as="parsed") # Получение данных запроса
      
      country <- content_data$data$attributes$country # Страна (Код)
      values <- unlist(content_data$data$attributes$`last_analysis_stats`) # Значение 
      max_index <- which.max(values)
      rating <- names(values)[max_index] # Максимальное значение рейтинга
      
      new_row <- data.frame(ip = ip,
                            country = ifelse(is.null(country), 'unfound', country),
                            rating = rating,
                            stringsAsFactors = FALSE)
      
      result_df <- rbind(saved_ips_df, new_row) # Добавление к текущему файлу csv с сохр. айпишниками - новые значения
      write.csv(result_df, "saved_ips.csv", row.names = FALSE) #Загрузка обновленной таблицы в csv файл
      return(result_df)
    } else {
      next # Тут момент спорный, если запрос не прошел - вообще не записывать целую строчку фрейма в итоговый датафрейм или, например, записать в страну и рейтинг - NA???
    }
  }
  
  # Функция для извлечения признаков
  extract_features <- function(conn_data, saved_ips) {
    features <- conn_data %>%
      group_by(src, dst) %>%
      mutate(
        syn_count = sum(conn_state %in% c("S0", "REJ")),
        ack_count = sum(!(conn_state %in% c("S0", "REJ"))),
        syn_ack_ratio = ifelse(ack_count == 0, syn_count, syn_count / ack_count),
        request_freq = n()
      ) %>%
      ungroup() %>%
      left_join(saved_ips, by = c("src" = "ip")) %>%
      mutate(
        suspicious_ip = ifelse(rating != "harmless", 1, 0),
        unfound_country = ifelse(country_src == "unfound", 1, 0)
      ) %>%
      select(syn_count, ack_count, syn_ack_ratio, request_freq, suspicious_ip, unfound_country)
    
    return(features)
  }
  
  # Функция обучения модели 
  train_iso_forest <- function(features) {
    model <- isolation.forest(
      features,
      ntrees = 100,
      seed = 42,
      nthreads = 4
    )
    return(model)
  }
  
  # Функция для парсинга файла conn.log от Zeek
  parse_zeek_conn_log <- function(file_path) {
    show_spinner()
    conn_data <- vroom(
      file_path,
      delim = "\t",
      comment = "#",
      col_names = FALSE
    )
    
    # Извлечение заголовков из файла
    headers <- readLines(file_path)
    headers <- headers[grep("^#fields", headers)]
    headers <- sub("^#fields\\s+", "", headers)
    headers <- strsplit(headers, "\\t")[[1]]
    
    # Присвоение имен столбцов
    colnames(conn_data) <- headers
    
    # Фильтрация, убираю лишние столбцы
    conn_data <- conn_data %>% mutate(
      date = format(as.POSIXct(ts, origin = "1970-01-01"), "%d.%m.%y"),
      time = format(as.POSIXct(ts, origin = "1970-01-01"), "%H:%M:%S")) %>% 
      rename(src = id.orig_h, src_port = id.orig_p, dst = id.resp_h, dst_port = id.resp_p, protocol = proto, is_local_src = local_orig, is_local_dst = local_resp) %>%
      mutate(rating_src = NA, country_src = NA, rating_dst = NA, country_dst = NA) %>%
      select(uid, date, time, src, src_port, orig_ip_bytes, is_local_src, rating_src, country_src, dst, dst_port, resp_ip_bytes, is_local_dst, rating_dst, country_dst, protocol, conn_state, history)
    
    # Чтение файла с сохраненными айпишниками
    saved_ips_df <- vroom("saved_ips.csv")
    
    for (i in 1:nrow(conn_data)) {
      row <- conn_data[i, ]
      
      if (nrow(saved_ips_df[saved_ips_df$ip == row$dst, ]) == 0 && row$is_local_dst == FALSE) {
        saved_ips_df <- check_ip_virustotal(row$dst, saved_ips_df)
      }
      
      conn_data[i, ]$rating_dst <- ifelse(row$is_local_dst == TRUE, "local", saved_ips_df[saved_ips_df$ip == row$dst, ]$rating)
      conn_data[i, ]$country_dst <- ifelse(row$is_local_dst == TRUE, "local", saved_ips_df[saved_ips_df$ip == row$dst, ]$country)
      
      if (nrow(saved_ips_df[saved_ips_df$ip == row$src, ]) == 0 && row$is_local_src == FALSE) {
        saved_ips_df <- check_ip_virustotal(row$src, saved_ips_df)
      }
      
      conn_data[i, ]$rating_src <- ifelse(row$is_local_src == TRUE, "local", saved_ips_df[saved_ips_df$ip == row$src, ]$rating)
      conn_data[i, ]$country_src <- ifelse(row$is_local_src == TRUE, "local", saved_ips_df[saved_ips_df$ip == row$src, ]$country)
    }
    
    return(conn_data)
  }
  
  create_map_points <- function(ips_data, world_data) {
    ips_data <- ips_data %>% filter(country_src != "unfound")
    if (nrow(ips_data) != 0) {
      ip_counts <- ips_data %>% 
        group_by(country_src) %>%
        summarise(ip_count = n())
      
      mean_count <- mean(ip_counts$ip_count)
      
      ip_counts <- ip_counts %>%
        mutate(
          group = case_when(
            ip_count <= mean_count ~ "small",
            ip_count > mean_count & ip_count <= 1.6 * mean_count ~ "medium",
            ip_count > 1.6 * mean_count ~ "big",
          )
        )
      
      merged_data <- left_join(ip_counts, world_data, by=c("country_src" = "code"))
      
      result <- merged_data %>%
        select(lat, long, name, country_src, ip_count, group, country.etc)
      
      return(result)
    } else {
      return(ips_data)
    }
  }
  
  color_palette <- colorFactor(
    palette = c("yellow", "orange", "red"), 
    domain = c('small', 'medium', 'big'),
    ordered = TRUE
  )
  
  options(shiny.maxRequestSize = 30 * 1024^2) # Ограничение загружаемого файла до 30МБ
  
  if (!file.exists('saved_ips.csv')) {
    empty_df <- data.frame(ip = character(),
                           country = character(),
                           rating = numeric(),
                           stringsAsFactors = FALSE)
    write.csv(empty_df, "saved_ips.csv", row.names = FALSE)
  }
  
  all_countries <- countrycode::codelist %>%
    select(country.name.en, iso2c) %>%
    filter(!is.na(iso2c)) %>%
    distinct()
  
  country_coords <- maps::world.cities %>%
    filter(capital == 1 | pop > 500000) %>% 
    group_by(country.etc) %>%
    slice(1) %>%
    ungroup() %>%
    select(country.etc, name, lat, long)
  
  world_countries <- all_countries %>%
    left_join(country_coords, by = c("country.name.en" = "country.etc")) %>%
    filter(!is.na(lat)) %>% 
    rename(
      country.etc = country.name.en,
      code = iso2c
    ) %>%
    select(country.etc, lat, long, name, code)
  
  observeEvent(input$fileData, { # Добавление слушателя событий, для отслеживания загрузки
    req(input$fileData) # Ожидание получения файла
    
    ext <- str_split(input$fileData$name, fixed("."))[[1]] %>% tail(1) # Получение расширения файла
    
    file_path <- FALSE
    
    if (!dir.exists('./data')) {
      dir.create('data')
    }
    
    tryCatch({
      if (ext == 'log') {
        file_name <- paste0(
          format(Sys.time(), "%Y-%m-%d_%H-%M-%S"),
          "_processed_data.csv"
        )
        file_path <- paste('data', file_name, sep="/")
        
        parsed_csv <- parse_zeek_conn_log(input$fileData$datapath)
        write.csv(parsed_csv, paste('data', file_name, sep="/"), row.names = FALSE)
      }
      else if(ext == 'csv') {
        file_path <- input$fileData$datapath
      }
      else {
        showNotification('Произошла непредвиденная ошибка!', type = "error")
      }
    })
    
    if (file_path != FALSE) {
      saved_ips <- vroom("saved_ips.csv")
      parsed_data_csv <- vroom(file_path)
      
      map_points <- create_map_points(parsed_data_csv, world_countries)
      
      model <- reactiveVal(NULL)
      
      #Извлечение признаков
      features <- extract_features(
        parsed_data_csv, 
        saved_ips
      )
      
      model(train_iso_forest(features))
      
      if(is.null(model())) {
        features <- extract_features(parsed_data_csv, saved_ips)
        new_model <- isolation.forest(features, ntrees = 100, seed = 42)
        model(new_model)
      }
      
      #Обработчик переобучения
      observeEvent(input$retrain_btn, {
        features <- extract_features(parsed_data_csv, saved_ips)
        new_model <- isolation.forest(features, ntrees = 100, seed = 42)
        model(new_model)
        showNotification("Модель успешно переобучена!", type = "message")
      })
      
      #Реактивное вычисление аномалий с учетом порога
      anomaly_data <- reactive({
        req(input$anomaly_threshold)
        parsed_data_csv %>%
          mutate(
            is_anomaly = ifelse(anomaly_score > input$anomaly_threshold, "ANOMALY", "NORMAL"),
            is_anomaly = factor(is_anomaly, levels = c("NORMAL", "ANOMALY"))
          )
      })
      
      # Реактивное вычисление данных с учетом всех фильтров - в теории должно работать по факту не работает пока
      filtered_anomaly_data <- reactive({
        req(anomaly_data())
        
        data <- anomaly_data()
        
        data
      })
      
      # Предсказание с динамическим порогом
      anomaly_scores <- predict(model(), features)
      
      # Обновляем данные с результатами
      parsed_data_csv <-
        parsed_data_csv %>%
          mutate(
            anomaly_score = anomaly_scores,
            is_anomaly = anomaly_score > input$anomaly_threshold
          )
      
      if (nrow(map_points) > 0) {
        group_ranges <- map_points %>%
          group_by(group) %>%
          summarise(
            min_ip = min(ip_count),
            max_ip = max(ip_count),
          ) %>%
          mutate(
            label = case_when(
              group == "small" ~ paste0("Small (", min_ip, "-", max_ip, ")"),
              group == "medium" ~ paste0("Medium (", min_ip, "-", max_ip, ")"),
              group == "big" ~ paste0("Big (", min_ip, "-", max_ip, ")")
            )
          )
        
        legend_colors <- c()
        
        if (nrow(group_ranges) == 1) {
          legend_colors <- c("red")
        } else if (nrow(group_ranges) == 2) {
          legend_colors <- c("red", "yellow")
        } else {
          legend_colors <- c("red", "orange", "yellow")
        }
        
        base_map <- function() {
          leaflet(map_points) %>% 
            addTiles() %>% # Добавление подложки
            setView(0.34580993652344, 50.6252978589571, zoom = 3) %>% # Установка начального зума и координат
            addCircleMarkers(
              ~long, ~lat,
              color = ~color_palette(group),
              stroke = FALSE,
              fillOpacity = 0.8,
              radius = 8,
              label = ~country.etc,
              popup = ~paste("<b>Количество ip-адресов:</b>", ip_count)
            ) %>%
            addLegend(
              "bottomright", 
              colors = legend_colors,
              labels = group_ranges$label,
              title = "Группы (диапазон IP-адресов)",
              opacity = 1
            )
        }
        
        top_map_points <- function() {
          points <- map_points %>%
            arrange(desc(ip_count)) %>%
            select(country_src, ip_count) %>%
            filter(country_src != 'local') %>%
            rename(country = country_src, count = ip_count) %>%
            head(3)
          
          datatable(
          points,
          rownames = FALSE,
          options = list(
            dom = 't',
            ordering = FALSE,
            autoWidth = TRUE,
            initComplete = JS(
              "function(settings, json) {",
              "  $(this.api().table().header()).css({'background-color': '#F82B26', 'color': '#0E1F27', 'fontSize': '18px'});",
              "}"
            )
          ) 
          ) %>% formatStyle(
            columns = names(points),
            target = "cell",
            color = "#4ECDC4",
            border = "1px solid #4ECDC4",
            fontFamily = "Courier New, monospace",
            fontWeight =  700,
            fontSize = '16px'
          )
        }
        
        output$top_map_points <- renderDT({ top_map_points() })
        
        output$map <- renderLeaflet({ base_map() })
      }
      
      ips_table <- function() {
        
        req(anomaly_data())
        
        datatable(
          anomaly_data() %>% mutate(
            anomaly_score = round(anomaly_score, 3)
          ) %>% select(-uid),
          rownames = FALSE,
          options = list(
            pageLength = 5,
            lengthMenu = c(5, 10, 15, 20),
            scrollX = TRUE,
            autoWidth = TRUE,
            initComplete = JS(
              "function(settings, json) {",
              "  $(this.api().table().header()).css({'background-color': '#F82B26', 'color': '#0E1F27', 'fontSize': '18px'});",
              "}"
            ),
            targets = which(names(anomaly_data()) == "is_anomaly") - 1
          ),
          escape = FALSE
        ) %>% formatStyle(
          columns = names(parsed_data_csv %>% select(-uid)),
          target = "cell",
          color = "#4ECDC4",
          border = "1px solid #4ECDC4",
          fontFamily = "Courier New, monospace",
          fontWeight =  700,
          fontSize = '18px'
        )
      }
      
      output$ip_table <- renderDT({ ips_table() })
      
      unique_count_src <- parsed_data_csv %>% distinct(src) %>% nrow()
      output$label_uniq_src <- renderText({"Количество уникальных ip-src"})
      output$text_uniq_src <- renderText({unique_count_src})
      
      unique_count_dst <- parsed_data_csv %>% distinct(dst) %>% nrow()
      output$label_uniq_dst <- renderText({"Количество уникальных ip-dst"})
      output$text_uniq_dst <- renderText({unique_count_dst})
      
      syn_count <- parsed_data_csv %>%
        filter((str_detect(conn_state, "S0") | str_detect(conn_state, "REJ")) & protocol=="tcp") %>% nrow()
      output$label_count_syn <- renderText({"Количество не установленных tcp-соединений"})
      output$text_count_syn <- renderText({syn_count})
      
      ack_count <- parsed_data_csv %>%
        filter(!(str_detect(conn_state, "S0") | str_detect(conn_state, "REJ")) & protocol=="tcp") %>% nrow()
      output$label_count_ack <- renderText({"Количество установленных tcp-соединений"})
      output$text_count_ack <- renderText({ack_count})
      
      
      filtered_data <- reactive({
        req(input$ip_table_rows_all)
        df <- parsed_data_csv[input$ip_table_rows_all, ]
        rownames(df) <- NULL
        df
      })
      
      pie_chart_protocols <- function() {
        protocols_table <- parsed_data_csv %>% select(protocol) %>% group_by(protocol) %>% summarise(count = n())
        
        plot_ly( protocols_table, 
                 labels = ~protocol, 
                 values = ~count, 
                 type = 'pie',
                 hole = 0.6,
                 textinfo = 'none',
                 hoverinfo = 'text',
                 text = ~paste("<b>Протокол:</b>", protocol, "\n<b>Кол-во:</b>", count),
                 marker = list(line = list(color = '#4ECDC4', width = 1))) %>%
          layout(title = list(text = "<b>Протоколы</b>", x = 0.5, y = 1),
                 font = list(color = "#4ECDC4", size = 18, family = 'Consolas'),
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "#4ECDC4", 
                                   font = list(color = "#0E1F27", size = 16)),
                 paper_bgcolor = "#0E1F27",
                 plot_bgcolor = "#0E1F27")
      }
      
      pie_chart_top_src_ip <- function() {
        ip_src_table <- parsed_data_csv %>% select(src) %>% group_by(src) %>% summarise(count = n()) %>% arrange(desc(count))
        
        plot_ly(ip_src_table, 
                labels = ~src, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("<b>IP:</b>", src, "\n<b>Кол-во:</b>", count),
                marker = list(line = list(color = '#4ECDC4', width = 1))) %>%
          layout(title = list(text = "<b>Ip-отправления</b>", x = 0.5, y = 1),
                 font = list(color = "#4ECDC4", size = 18, family = 'Consolas'),
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "#4ECDC4", 
                                   font = list(color = "#0E1F27", size = 16)),
                 paper_bgcolor = "#0E1F27",
                 plot_bgcolor = "#0E1F27")
      }
      
      pie_chart_top_dst_ip <- function() {
        ip_dst_table <- parsed_data_csv %>% select(dst) %>% group_by(dst) %>% summarise(count = n()) %>% arrange(desc(count))
        
        plot_ly(ip_dst_table, 
                labels = ~dst, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("<b>IP:</b>", dst, "\n<b>Кол-во:</b>", count),
                marker = list(line = list(color = '#4ECDC4', width = 1))) %>%
          layout(title = list(text = "<b>Ip-назначения</b>", x = 0.5, y = 1),
                 font = list(color = "#4ECDC4", size = 18, family = 'Consolas'),
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "#4ECDC4", 
                                   font = list(color = "#0E1F27", size = 16)),
                 paper_bgcolor = "#0E1F27",
                 plot_bgcolor = "#0E1F27")
      }
      
      pie_chart_top_src_port <- function() {
        port_src_table <- parsed_data_csv %>% select(src_port) %>% group_by(src_port) %>% summarise(count = n()) %>% arrange(desc(count))
        
        plot_ly(port_src_table, 
                labels = ~src_port, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("<b>Port:</b>", src_port, "\n<b>Кол-во:</b>", count),
                marker = list(line = list(color = '#4ECDC4', width = 1))) %>%
          layout(title = list(text = "<b>Порты отправления</b>", x = 0.5, y = 1),
                 font = list(color = "#4ECDC4", size = 18, family = 'Consolas'),
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "#4ECDC4", 
                                   font = list(color = "#0E1F27", size = 16)),
                 paper_bgcolor = "#0E1F27",
                 plot_bgcolor = "#0E1F27")
      }
      
      pie_chart_top_dst_port <- function() {
        port_dst_table <- parsed_data_csv %>% select(dst_port) %>% group_by(dst_port) %>% summarise(count = n()) %>% arrange(desc(count))
        
        plot_ly(port_dst_table, 
                labels = ~dst_port, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("<b>Port:</b>", dst_port, "\n<b>Count:</b>", count),
                marker = list(line = list(color = "#4ECDC4", width = 1))) %>%
          layout(title = list(text = "<b>Порты назначения</b>", x = 0.5, y = 1),
                 font = list(color = "#4ECDC4", size = 18, family = 'Consolas'),
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "#4ECDC4", 
                                   font = list(color = "#0E1F27", size = 16)),
                 paper_bgcolor = "#0E1F27",
                 plot_bgcolor = "#0E1F27")
      }
      
      output$pie_chart_protocols <- renderPlotly({ pie_chart_protocols() })
      
      output$pie_chart_top_src_ip <- renderPlotly({ pie_chart_top_src_ip() })
      
      output$pie_chart_top_dst_ip <- renderPlotly({ pie_chart_top_dst_ip() })
      
      output$pie_chart_top_src_port <- renderPlotly({ pie_chart_top_src_port() })
      
      output$pie_chart_top_dst_port <- renderPlotly({ pie_chart_top_dst_port() })
      
      # Графики
      # График активности ip-адреса
      processed_data_ips <- reactive({
        df <- parsed_data_csv
        
        df <- df %>%
          mutate(
            datetime = as.POSIXct(paste(date, time), format = "%d.%m.%Y %H:%M:%S"),
            time_sec = format(datetime, "%H:%M:%S"),
            time_min = format(datetime, "%H:%M"),
            time_hour = format(datetime, "%H:00")
          )
        
        df
      })
      
      # Обновляем список IP-адресов в зависимости от выбранного типа (src или dst)
      observe({
        df <- processed_data_ips()
        ip_column <- if(input$ipType == "src") "src" else "dst"
        
        updateSelectInput(session, "selectedIP", 
                          choices = unique(df[[ip_column]]))
      })
      
      # Подготовка данных для графика
      plot_data_ips <- reactive({
        req(input$selectedIP)
        df <- processed_data_ips()
        
        # Фильтруем по выбранному IP (src или dst)
        ip_column <- input$ipType
        filtered <- df %>% 
          filter(!!sym(ip_column) == input$selectedIP)
        
        # Группируем в зависимости от выбранного временного разрешения
        time_col <- case_when(
          input$timeGrouping == "sec" ~ "time_sec",
          input$timeGrouping == "min" ~ "time_min",
          input$timeGrouping == "hour" ~ "time_hour"
        )
        
        # Определяем, какой столбец использовать для подсчета уникальных значений
        count_column <- if(ip_column == "src") "dst" else "src"
        
        grouped <- filtered %>%
          group_by(time = !!sym(time_col)) %>%
          summarise(
            total_connections = n(),
            unique_connections = n_distinct(!!sym(count_column)),
            .groups = "drop"
          ) %>%
          arrange(time)
        
        grouped
      })
      
      ip_activity_plot <- function() {
        data <- plot_data_ips()
        req(nrow(data) > 0)
        
        # Определяем заголовок оси Y в зависимости от типа IP
        y_title <- if(input$ipType == "src") {
          "Количество получателей (dst)"
        } else {
          "Количество отправителей (src)"
        }
        
        plot_ly(data, x = ~time, y = ~total_connections, 
                type = 'bar',
                name = 'Всего соединений',
                marker = list(color = 'rgba(78, 205, 196, 0.4)',
                              line = list(color = 'rgba(78, 205, 196, 1.0)', width = 1))) %>%
          layout(
            title = list(text = paste("<b>Активность IP-адреса", input$selectedIP, 
                                      if(input$ipType == "src") "(источник)" else "(получатель)", "</b>"),
                         x = 0.5, y = 1),
            font = list(color = "#4ECDC4", size = 18, family = 'Consolas'),
            xaxis = list(
              title = "<b>Время</b>",
              type = "category",
              tickangle = 45,
              categoryorder = "array",
              categoryarray = ~time
            ),
            yaxis = list(title = y_title),
            margin = list(b = 150),
            hovermode = "x unified",
            barmode = 'group',
            paper_bgcolor = "#0E1F27",
            plot_bgcolor = "#0E1F27"
          )
      }
      
      output$ipActivityPlot <- renderPlotly({ ip_activity_plot() })
      
      top_dst_ip <- parsed_data_csv %>% group_by(dst) %>% summarise(total = n()) %>% arrange(desc(total)) %>% head(1) %>% pull(dst) %>% .[1]
      top_port_dst_ip <- parsed_data_csv %>% filter(dst==top_dst_ip) %>% group_by(dst_port) %>% summarise(total = n()) %>% arrange(desc(total)) %>% head(1) %>% pull(dst_port) %>% .[1]
      count_uniq_ip_address <- parsed_data_csv %>% filter(dst == top_dst_ip & dst_port == top_port_dst_ip) %>% summarise(unique_src = n_distinct(src)) %>% pull(unique_src) %>% .[1]
      
      
      output$label_top_dst_ip <- renderText({"Самый используемый ip-dst:port"})
      output$text_top_dst_ip <- renderText({paste(top_dst_ip, top_port_dst_ip, sep=":")})
      
      # График подключений
      df <- reactive({
        parsed_data_csv
      })
      
      observe({
        data <- df() %>% filter(protocol == 'tcp')
        
        updateSelectInput(session, "date_select", 
                          choices = unique(data$date),
                          selected = unique(data$date)[1])
        
        updateSelectInput(session, "ip_select",
                          choices = unique(data$dst),
                          selected = unique(data$dst)[1])
      })
      
      observe({
        req(input$ip_select)
        
        data <- df() %>% 
          filter(protocol == 'tcp' & dst %in% input$ip_select)
        
        updateSelectInput(session, "port_select",
                          choices = unique(data$dst_port),
                          selected = unique(data$dst_port)[1])
      })
      
      plot_data <- reactive({
        req(input$date_select)
        
        data <- df() %>%
          filter(date == input$date_select)
        
        if (!is.null(input$ip_select) && length(input$ip_select) > 0) {
          data <- data %>% filter(dst %in% input$ip_select)
        }
        
        if (!is.null(input$port_select) && length(input$port_select) > 0) {
          data <- data %>% filter(dst_port %in% input$port_select)
        }
        
        data <- data %>%
          mutate(datetime = dmy_hms(paste(date, time)))
        
        if (input$time_group == "hour") {
          data <- data %>%
            mutate(time_group = floor_date(datetime, "hour"))
        } else if (input$time_group == "minute") {
          data <- data %>%
            mutate(time_group = floor_date(datetime, "minute"))
        } else {
          data <- data %>%
            mutate(time_group = floor_date(datetime, "second"))
        }
        
        syn_data <- data %>%
          filter(str_detect(conn_state, "S0") | str_detect(conn_state, "REJ")) %>%
          group_by(time_group) %>%
          summarise(syn_count = n(), .groups = "drop")
        
        ack_data <- data %>%
          filter(!(str_detect(conn_state, "S0") | str_detect(conn_state, "REJ"))) %>%
          group_by(time_group) %>%
          summarise(ack_count = n(), .groups = "drop")
        
        full_join(syn_data, ack_data, by = "time_group") %>%
          replace_na(list(syn_count = 0, ack_count = 0)) %>%
          arrange(time_group)
      })
      
      syn_ack_plot <- function() {
        data <- plot_data()
        
        time_format <- if (input$time_group == "hour") "%H:%M" 
        else if (input$time_group == "minute") "%H:%M" 
        else "%H:%M:%S"
        
        plot_ly(data) %>%
          add_lines(x = ~time_group, y = ~syn_count, name = "Не установлено", 
                    line = list(color = '#F82B26'), yaxis = "y1") %>%
          add_lines(x = ~time_group, y = ~ack_count, name = "Установлено", 
                    line = list(color = '#4ECDC4'), yaxis = "y1") %>%
          layout(
            font = list(color = '#4ECDC4', size = 18, family = 'Consolas'),
            title = list(text = "<b>Tcp-соединение</b>", x = 0.5, y = 1),
            xaxis = list(
              title = "Время",
              type = "date",
              tickformat = time_format,
              gridcolor = 'rgba(78, 205, 196, 0.4)'
            ),
            yaxis = list(
              title = "Количество пакетов",
              side = "left",
              gridcolor = 'rgba(78, 205, 196, 0.4)'
            ),
            legend = list(x = 0.1, y = 0.9),
            hovermode = "x unified",
            paper_bgcolor = "#0E1F27",
            plot_bgcolor = "#0E1F27"
          )
      }
      
      output$syn_ack_plot <- renderPlotly({ syn_ack_plot() })
        
        # Вывод аномалий
        check_anomaly <- reactive({
          data <- plot_data()
          
          total_syn <- sum(data$syn_count, na.rm = TRUE)
          total_ack <- sum(data$ack_count, na.rm = TRUE)
          
          if (total_ack > 0) {
            ratio <- total_syn / total_ack
            
            if (ratio > 0.15) {
              return("Возможна аномальная активность")
            }
          }
          
          return("Аномалий нет")
        })
        
        output$anomaly_status <- renderText({
          check_anomaly()
        })
        
        # График с объемом трафика
        data_traffic_value <- parsed_data_csv %>% mutate(
          datetime = dmy_hms(paste(date, time)),
          sent_bytes = orig_ip_bytes,
          received_bytes = resp_ip_bytes
        ) %>% select(datetime, sent_bytes, received_bytes) %>%
          arrange(datetime)
        
        traffic_plot <- function() {
          req(data_traffic_value)
          
          plot_ly(data_traffic_value, x = ~datetime) %>%
            add_trace(
              y = ~sent_bytes,
              name = "Получено",
              type = 'scatter',
              mode = 'lines',
              fill = 'tozeroy',
              fillcolor = 'rgba(255,107,107,0.5)',
              line = list(color = 'rgba(255,107,107,1)')
            ) %>%
            add_trace(
              y = ~received_bytes,
              name = "Отправлено",
              type = 'scatter',
              mode = 'lines',
              fill = 'tozeroy',
              fillcolor = 'rgba(78,205,196,0.5)',
              line = list(color = 'rgba(78,205,196,1)')
            ) %>%
            layout(
              hovermode = "x unified",
              font = list(color = '#4ECDC4', size = 18, family = 'Consolas'),
              title = list(text = "<b>Объем трафика</b>", x = 0.5, y = 1),
              yaxis = list(
                title = "Объем трафика", 
                gridcolor = "rgba(78, 205, 196, 0.4)",
                zerolinecolor = "#e1e1e1"
              ),
              xaxis = list(
                title = "Время", 
                gridcolor = "rgba(78, 205, 196, 0.4)",
                zerolinecolor = "#e1e1e1"
              ),
              plot_bgcolor = "#0E1F27",
              paper_bgcolor = "#0E1F27",
              legend = list(
                x = 0.9,
                y = 0.9
              ),
              showlegend = TRUE
            )
        }
        
        output$traffic_plot <- renderPlotly({ traffic_plot() })
        
        count_traffic_src <- data_traffic_value %>% select(sent_bytes) %>% summarise(total = sum(sent_bytes)) %>% pull(total) %>% .[1]
        output$label_src_traffic <- renderText({"Полученные байты"})
        output$text_src_traffic <- renderText({count_traffic_src})
        
        count_traffic_dst <- data_traffic_value %>% select(received_bytes) %>% summarise(total = sum(received_bytes)) %>% pull(total) %>% .[1]
        output$label_dst_traffic <- renderText({"Отправленные байты"})
        output$text_dst_traffic <- renderText({count_traffic_dst})
        
        # Визуализация аномалий
        output$anomaly_plot <- renderPlotly({
          req(anomaly_data())
          
          plot_data <- anomaly_data()
          
          plot_ly(plot_data, x = ~time, y = ~anomaly_score, 
                  color = ~is_anomaly, 
                  colors = c("NORMAL" = "#4ECDC4", "ANOMALY" = "#F82B26"),
                  type = "scatter", mode = "markers",
                  text = ~paste("IP:", src, "<br>Рейтинг:", round(anomaly_score, 2))) %>%
            layout(
              hovermode = "x unified",
              font = list(color = '#4ECDC4', size = 18, family = 'Consolas'),
              title = list(text = paste("<b>Аномальная активность (порог:", input$anomaly_threshold, ")</b>"), x = 0.5, y = 1),
              yaxis = list(
                title = "Рейтинг", 
                gridcolor = "rgba(78, 205, 196, 0.4)",
                zerolinecolor = "#e1e1e1"
              ),
              xaxis = list(
                title = "Время", 
                gridcolor = "rgba(78, 205, 196, 0.4)",
                zerolinecolor = "#e1e1e1"
              ),
              plot_bgcolor = "#0E1F27",
              paper_bgcolor = "#0E1F27",
              shapes = list(
                list(
                  type = "line",
                  y0 = input$anomaly_threshold,
                  y1 = input$anomaly_threshold,
                  x0 = 0,
                  x1 = 1,
                  xref = "paper",
                  line = list(color = "#F82B26", dash = "dot")
                )
              )
            )
        })
        
        # Лоадер и инпут
        output$file_loaded <- reactive({
          !is.null(parsed_data_csv)
        })
        
        outputOptions(output, "file_loaded", suspendWhenHidden = FALSE)
        
        hide_spinner()
        
        output$download_html <- downloadHandler(
          file_name <- paste0(
            format(Sys.time(), "%d.%m.%Y_%H:%M:%S"),
            "_report.html"
          ),
          content = function(file) {
            res <- rmarkdown::render(
              "report_conf/report_template_html.Rmd",
              params = list(
                draw_map = base_map,
                draw_ips_table = ips_table,
                draw_chart_protocols = pie_chart_protocols,
                draw_chart_top_src_ip = pie_chart_top_src_ip,
                draw_chart_top_dst_ip = pie_chart_top_dst_ip,
                draw_chart_top_src_port = pie_chart_top_src_port,
                draw_chart_top_dst_port = pie_chart_top_dst_port,
                draw_ip_activity = ip_activity_plot,
                draw_syn_ack_plot = syn_ack_plot,
                draw_traffic_plot = traffic_plot,
                title_file = file_name
              )
            )
            file.rename(res, file)
          }
        )
    }
  })
}