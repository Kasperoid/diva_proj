library(shiny)
library(stringr)
library(dplyr)
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
  
  # Функция для парсинга файла conn.log от Zeek
  parse_zeek_conn_log <- function(file_path) {
    conn_data <- read_delim(
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
      select(uid, date, time, src, src_port, is_local_src, rating_src, country_src, dst, dst_port, is_local_dst, rating_dst, country_dst, protocol, conn_state, history)
    
    # Чтение файла с сохраненными айпишниками
    saved_ips_df <- read.csv("saved_ips.csv", stringsAsFactors = FALSE)
    
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
  
  world.cities <- maps::world.cities %>% # Получение данных из таблицы world.cities
    filter(capital == 1) %>% # Получить только столицы
    select(country.etc, lat, long, name) %>% # Выбрать из таблицы название страны, город, широту, долготу
    mutate(code = countrycode(country.etc, "country.name", "iso2c")) %>% # Полученеи кода страны
    filter(!is.na(code)) # Фильтрация NA
  
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
        showNotification('Обработка прошла успешно!', type = "default")
        
      }
      else if(ext == 'csv') {
        file_path <- input$fileData$datapath
      }
      else {
        showNotification('Произошла непредвиденная ошибка!', type = "error")
      }
    })
    
    if (file_path != FALSE) {
      parsed_data_csv <- read.csv(file_path, stringsAsFactors = FALSE)
      map_points <- create_map_points(parsed_data_csv, world.cities)
      
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
        
        output$map <- renderLeaflet({ base_map() })
      }
      
      output$download_html <- downloadHandler(
        file_name <- paste0(
          format(Sys.time(), "%Y-%m-%d_%H-%M-%S"),
          "_report.html"
        ),
        content = function(file) {
          res <- rmarkdown::render(
            "report_conf/report_template_html.Rmd",
            params = list(
              draw_map = base_map,
              #ip_table = base_ip_table
            )
          )
          file.rename(res, file)
        }
      )
      
      output$ip_table <- renderDT({ 
        datatable(
        parsed_data_csv %>% select(-uid),
        rownames = FALSE,
        options = list(
          pageLength = 5,
          lengthMenu = c(5, 10, 15, 20),
          scrollX = TRUE,
          autoWidth = TRUE
        )
        ) 
      })
      
      filtered_data <- reactive({
        req(input$ip_table_rows_all)
        df <- parsed_data_csv[input$ip_table_rows_all, ]
        rownames(df) <- NULL
        df
      })
      
      base_ip_table <- function() {
        datatable(
          parsed_data_csv,
          rownames = FALSE,
          options = list(
            pageLength = 5,
            lengthMenu = c(5, 10, 15, 20),
            scrollX = TRUE,
            autoWidth = TRUE
          )
        )
      }
      
      output$pie_chart_protocols <- renderPlotly({
        protocols_table <- parsed_data_csv %>% select(protocol) %>% group_by(protocol) %>% summarise(count = n())
        
        plot_ly( protocols_table, 
                 labels = ~protocol, 
                 values = ~count, 
                 type = 'pie',
                 hole = 0.6,
                 textinfo = 'none',
                 hoverinfo = 'text',
                 text = ~paste("Protocol:", protocol, "\nCount:", count),
                 marker = list(line = list(color = '#FFFFFF', width = 1))) %>%
          layout(title = "Protocols",
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "white", 
                                   font = list(color = "black")))
      })
      
      output$pie_chart_top_src_ip <- renderPlotly({
        ip_src_table <- parsed_data_csv %>% select(src) %>% group_by(src) %>% summarise(count = n()) %>% arrange(desc(count)) %>% head(10)
        
        plot_ly(ip_src_table, 
                labels = ~src, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("IP:", src, "\nCount:", count),
                marker = list(line = list(color = '#FFFFFF', width = 1))) %>%
          layout(title = "Top 10 source IPs",
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "white", 
                                   font = list(color = "black")))
      })
      
      output$pie_chart_top_dst_ip <- renderPlotly({
        ip_dst_table <- parsed_data_csv %>% select(dst) %>% group_by(dst) %>% summarise(count = n()) %>% arrange(desc(count)) %>% head(10)
        
        plot_ly(ip_dst_table, 
                labels = ~dst, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("IP:", dst, "\nCount:", count),
                marker = list(line = list(color = '#FFFFFF', width = 1))) %>%
          layout(title = "Top 10 distance IPs",
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "white", 
                                   font = list(color = "black")))
      })
      
      output$pie_chart_top_src_port <- renderPlotly({
        port_src_table <- parsed_data_csv %>% select(src_port) %>% group_by(src_port) %>% summarise(count = n()) %>% arrange(desc(count)) %>% head(10)
        
        plot_ly(port_src_table, 
                labels = ~src_port, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("Port:", src_port, "\nCount:", count),
                marker = list(line = list(color = '#FFFFFF', width = 1))) %>%
          layout(title = "Top 10 source ports",
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "white", 
                                   font = list(color = "black")))
      })
      
      output$pie_chart_top_dst_port <- renderPlotly({
        port_dst_table <- parsed_data_csv %>% select(dst_port) %>% group_by(dst_port) %>% summarise(count = n()) %>% arrange(desc(count)) %>% head(10)
        
        plot_ly(port_dst_table, 
                labels = ~dst_port, 
                values = ~count, 
                type = 'pie',
                hole = 0.6,
                textinfo = 'none',
                hoverinfo = 'text',
                text = ~paste("Port:", dst_port, "\nCount:", count),
                marker = list(line = list(color = '#FFFFFF', width = 1))) %>%
          layout(title = "Top 10 distance ports",
                 showlegend = TRUE,
                 hoverlabel = list(bgcolor = "white", 
                                   font = list(color = "black")))
      })
    }
  })
}