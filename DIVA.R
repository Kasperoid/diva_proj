library(dplyr)
library(lubridate)
library(sys)
library("rjson")

# Обработка JSON в формат датафрейма
process_wireshark_json <- function(json_file) {
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
      protocol = protocol,
      stringsAsFactors = FALSE
    )
    
    result <- rbind(result, new_row)
  }
  
  return(result)
}

json_file <- "testMiniJson.json"
result_df <- process_wireshark_json(json_file)

write.csv(result_df, "processed_packets.csv", row.names = FALSE)