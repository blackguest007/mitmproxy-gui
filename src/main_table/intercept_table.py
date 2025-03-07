# path: /src/main_table/intercept_table.py


from PyQt6.QtCore import QDateTime
from PyQt6.QtWidgets import QTableWidgetItem

class PacketTableUpdater:
    def __init__(self, window):
        self.window = window  # 保存窗口对象，以便后续更新表格

    # 更新 intercept_table 中的字段
    def update_packet_table(self, data):
        """ 更新 QTableWidget 中的数据显示 """
        current_time = QDateTime.currentDateTime().toString("yyyy-MM-dd hh:mm:ss")

        row_position = self.window.packet_table.rowCount()  # 获取当前表格的行数
        self.window.packet_table.insertRow(row_position)  # 插入新的一行

        # 填充数据
        self.window.packet_table.setItem(row_position, 0, QTableWidgetItem(current_time))
        self.window.packet_table.setItem(row_position, 1, QTableWidgetItem(data['type']))
        self.window.packet_table.setItem(row_position, 2, QTableWidgetItem(data['direction']))  # 显示方向
        self.window.packet_table.setItem(row_position, 3, QTableWidgetItem(data['method']))
        self.window.packet_table.setItem(row_position, 4, QTableWidgetItem(data['url']))
        self.window.packet_table.setItem(row_position, 5, QTableWidgetItem(str(data['status_code'])))
        self.window.packet_table.setItem(row_position, 6, QTableWidgetItem(str(data['length'])))
