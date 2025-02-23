library(dplyr)
library(lubridate)
library(sys)
library("rjson")
library(httr)
source("config.R")

# API_KEY от virusTotal
api_url <- 'https://www.virustotal.com/api/v3/ip_addresses/'

# Получение рейтинга и страны через запрос на API virusTotal (v3)
check_ip_virustotal <- function(ip, saved_ips_df) {
  reqUrl <- sprintf("%s%s", api_url, ip)
  response <- GET(url=reqUrl, add_headers(.headers=c('X-Apikey' = api_key)))
  Sys.sleep(5)
  if (status_code(response) == 200) {
    content_data <- content(response, as="parsed")
    
    country = content_data$data$attributes$country
    values <- unlist(content_data$data$attributes$`last_analysis_stats`)
    max_index <- which.max(values)
    rating <- names(values)[max_index]
    
    new_row <- data.frame(ip = ip,
                          country = country,
                          rating = rating,
                          stringsAsFactors = FALSE)
    result_df <- rbind(saved_ips_df, new_row)
    write.csv(result_df, "saved_ips.csv", row.names = FALSE)
    return(result_df)
  } else {
    next # Тут момент спорный, если запрос не прошел - вообще не записывать целую строчку фрейма в итоговый датафрейм или, например, записать в страну и рейтинг - NA???
  }
}

# Обработка JSON в формат датафрейма
process_wireshark_json <- function(json_file) {
  saved_ips_df <- read.csv("saved_ips.csv", stringsAsFactors = FALSE)
  # Чтение JSON файла
  data <- fromJSON(paste(readLines(json_file), collapse=""))
  
  # Пустой датафрейм 
  result <- data.frame(
    dst = character(),
    src = character(),
    length = character(),
    date = as.POSIXct(character()),
    time = as.POSIXct(character()),
    port = character(),
    ack = character(),
    sync = character(),
    name_dst = character(),
    name_src = character(),
    rating_src = character(),
    rating_dst = character(),
    country_dst = character(),
    country_src = character(),
    protocol = character(),
    stringsAsFactors = FALSE
  )
  
  # Обработка каждого фрейма из JSON, если какого то значения нет - пропуск пакета, он не записывается в результирующий фрейм
  for (packet in data) {
    layers <- packet$`_source`$layers
    
    # Блок с получением Ip src и dst + названия
    if (!is.null(layers$ip)) {
      src <- layers$ip$`ip.src`
      dst <- layers$ip$`ip.dst`
      name_src <- layers$eth$`eth.src_tree`$`eth.addr.oui_resolved`
      name_dst <- layers$eth$`eth.dst_tree`$`eth.addr.oui_resolved`
    } else {
      next
    }
    
    # Получение даты и времени сразу их форматирование + получение длины пакета
    if (!is.null(layers$frame)) {
      getDate <- as.POSIXct(as.numeric(layers$frame$`frame.time_epoch`), origin="1970-01-01")
      date <- format(getDate, "%d.%m.%Y")
      time <- format(getDate, "%H:%M:%S")
      length <- layers$frame$`frame.len`
    } else {
      next
    }
    
    # Получение порта и флагов sync ack
    if (!is.null(layers$tcp)) {
      port <- layers$tcp$`tcp.dstport`
      ack <- ifelse(!is.null(layers$tcp$`tcp.flags_tree`$`tcp.flags.ack`) && 
                      layers$tcp$`tcp.flags_tree`$`tcp.flags.ack` == "1", "1", "0")
      sync <- ifelse(!is.null(layers$tcp$`tcp.flags_tree`$`tcp.flags.syn`) && 
                       layers$tcp$`tcp.flags_tree`$`tcp.flags.syn` == "1", "1", "0")
    } else {
      next
    }
    
    # Получение протокола
    protocol <- if (!is.null(layers$frame$`frame.protocols`)) {
      layers$frame$`frame.protocols`
    } else {
      next
    }
    
    # Проверка найден ли ip в датафрейме сохраненных, если нет - то отправка запроса на сервер virusTotal
    if (nrow(saved_ips_df[saved_ips_df$ip == dst, ]) == 0) {
      saved_ips_df <- check_ip_virustotal(dst, saved_ips_df)
    } 
    rating_dst = saved_ips_df[saved_ips_df$ip == dst, ]$rating
    country_dst =  saved_ips_df[saved_ips_df$ip == dst, ]$country
    
    if (nrow(saved_ips_df[saved_ips_df$ip == src, ]) == 0) {
      saved_ips_df <- check_ip_virustotal(src, saved_ips_df)
    }
    rating_src = saved_ips_df[saved_ips_df$ip == src, ]$rating
    country_src =  saved_ips_df[saved_ips_df$ip == src, ]$country
    
    print(dst)
    print(src)
    print(rating_src)
    print(country_src)
    
    # Добавление строки в фрейм
    new_row <- data.frame(
      dst = dst,
      src = src,
      length = length,
      date = date,
      time = time,
      port = port,
      ack = ack,
      sync = sync,
      name_dst = name_dst,
      name_src = name_src,
      rating_src = rating_src,
      rating_dst = rating_dst,
      country_dst = country_dst,
      country_src = country_src,
      protocol = protocol,
      stringsAsFactors = FALSE
    )
    
    result <- rbind(result, new_row)
  }
  
  return(result)
}

# Проверка существует ли файл с сохраненными ip
if (!file.exists('saved_ips.csv')) {
  empty_df <- data.frame(ip = character(),
                         country = character(),
                         rating = numeric(),
                         stringsAsFactors = FALSE)
  write.csv(empty_df, "saved_ips.csv", row.names = FALSE)
}

json_file <- "testMiniJson.json"
result_df <- process_wireshark_json(json_file)

write.csv(result_df, "processed_packets.csv", row.names = FALSE)